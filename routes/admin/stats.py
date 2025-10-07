from flask import Blueprint, render_template, request, redirect, url_for, session, flash
import pickle
import numpy as np
from phe import paillier
import traceback

# CORRECTED: Use absolute imports
from database import get_db_connection
from crypto import get_phe_keys, phe_decrypt, generate_sse_token
# Assuming blockchain.py is at the root
import blockchain

# Import DP library safely
try:
    from diffprivlib.tools.mean import mean as dp_mean
except ImportError:
    print("Warning: diffprivlib not found. Statistics will not be differentially private.")
    def dp_mean(data, epsilon=None, range=None):
        if not data: return 0
        valid_data = [x for x in data if x is not None]
        if not valid_data: return 0
        return np.mean(valid_data)

# Define the Blueprint for stats
# REMOVED template_folder argument
admin_stats_bp = Blueprint('admin_stats', __name__)

# --- Helper - Load PHE keys only once ---
try:
    _, PHE_PRIVATE_KEY = get_phe_keys()
except Exception as e:
    print(f"CRITICAL ERROR: Could not load PHE keys in admin stats blueprint: {e}")
    PHE_PRIVATE_KEY = None

# --- Statistics Routes ---

@admin_stats_bp.route('/statistics', methods=['POST'])
def run_overall_statistics():
    """Performs secure, differentially private avg heart rate."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if not PHE_PRIVATE_KEY:
         flash("PHE Private Key not loaded. Cannot perform statistics.", "danger")
         return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT phe_heart_rate FROM medical_records WHERE phe_heart_rate IS NOT NULL").fetchall()
        conn.close()

        if not rows:
            flash("No heart rate data found to analyze.", "warning")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        encrypted_hrs = []
        deserialization_errors = 0
        for row in rows:
            try:
                encrypted_num = phe_decrypt(PHE_PRIVATE_KEY, row['phe_heart_rate'], deserialize_only=True)
                if encrypted_num: encrypted_hrs.append(encrypted_num)
                else: deserialization_errors += 1
            except Exception as e:
                print(f"Could not deserialize PHE heart rate data: {e}")
                deserialization_errors += 1

        if not encrypted_hrs:
            flash(f"Found {len(rows)} HR points, but failed to deserialize valid ones.", "danger")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        count = len(encrypted_hrs)
        encrypted_sum = sum(encrypted_hrs)
        plain_sum = phe_decrypt(PHE_PRIVATE_KEY, encrypted_sum)

        if plain_sum is None: raise Exception("PHE decryption of final sum failed.")

        true_average = plain_sum / count
        data_bounds = [0, 250]; epsilon = 0.5
        sensitivity = (data_bounds[1] - data_bounds[0]) / count if count > 0 else 0
        scale = sensitivity / epsilon if epsilon > 0 else float('inf')
        noise = np.random.laplace(loc=0.0, scale=scale if scale != float('inf') else 0, size=1)[0]
        dp_average = np.clip(true_average + noise, data_bounds[0], data_bounds[1])

        blockchain.log_action_to_blockchain(
            user_id=session['user_id'], action="RUN_STATISTICS",
            details=f"Calculated DP avg HR (e={epsilon}) on {count} records. Errors: {deserialization_errors}"
        )
        session['statistics'] = {
            'query': 'Average Heart Rate (All Patients)', 'count': count,
            'true_average': f"{true_average:.2f}", 'dp_average': f"{dp_average:.2f}",
            'epsilon': epsilon, 'deserialization_errors': deserialization_errors
        }
        flash("Statistical analysis complete!", "success")

    except Exception as e:
        print(f"Error during overall statistics: {e}")
        flash(f"An error occurred during statistical analysis: {e}", "danger")
        traceback.print_exc()

    return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect


@admin_stats_bp.route('/conditional_statistics', methods=['POST'])
def run_conditional_statistics():
    """Performs secure statistics on a subset based on SSE keyword."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if not PHE_PRIVATE_KEY:
         flash("PHE Private Key not loaded. Cannot perform statistics.", "danger")
         return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

    try:
        statistic_field = request.form.get('statistic_field')
        search_keyword = request.form.get('search_keyword')

        if not statistic_field or not search_keyword:
            flash("Statistic field and search keyword are required.", "warning")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        allowed_fields = {
            'phe_weight': 'Weight (kg)', 'phe_height': 'Height (cm)', 'phe_heart_rate': 'Heart Rate (bpm)'
        }
        if statistic_field not in allowed_fields:
            flash("Invalid statistic field selected.", "danger")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect
        human_readable_field = allowed_fields[statistic_field]

        search_token = generate_sse_token(search_keyword)
        conn = get_db_connection()
        record_ids_rows = conn.execute("SELECT record_id FROM search_index WHERE keyword_token = ?", (search_token,)).fetchall()

        if not record_ids_rows:
            flash(f"No records found matching diagnosis '{search_keyword}'.", "info")
            conn.close(); return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        record_ids = [row['record_id'] for row in record_ids_rows]
        placeholders = ','.join('?' for _ in record_ids)
        query = f"SELECT {statistic_field} FROM medical_records WHERE record_id IN ({placeholders}) AND {statistic_field} IS NOT NULL"
        rows = conn.execute(query, record_ids).fetchall()
        conn.close()

        if not rows:
            flash(f"Records found for '{search_keyword}', but none have {human_readable_field} data.", "info")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        encrypted_values = []
        deserialization_errors = 0
        for row in rows:
            try:
                encrypted_num = phe_decrypt(PHE_PRIVATE_KEY, row[0], deserialize_only=True)
                if encrypted_num: encrypted_values.append(encrypted_num)
                else: deserialization_errors += 1
            except Exception: deserialization_errors += 1

        if not encrypted_values:
            flash(f"Failed to deserialize {human_readable_field} data for matching records.", "danger")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        count = len(encrypted_values)
        encrypted_sum = sum(encrypted_values)
        plain_sum = phe_decrypt(PHE_PRIVATE_KEY, encrypted_sum)

        if plain_sum is None: raise Exception("PHE decryption of conditional sum failed.")

        true_average = plain_sum / count
        data_bounds = [0, 300]; epsilon = 0.5 # Generic bounds
        sensitivity = (data_bounds[1] - data_bounds[0]) / count if count > 0 else 0
        scale = sensitivity / epsilon if epsilon > 0 else float('inf')
        noise = np.random.laplace(loc=0.0, scale=scale if scale != float('inf') else 0, size=1)[0]
        dp_average = np.clip(true_average + noise, data_bounds[0], data_bounds[1])

        blockchain.log_action_to_blockchain(
            user_id=session['user_id'], action="RUN_CONDITIONAL_STATISTICS",
            details=f"Calculated DP avg {human_readable_field} (e={epsilon}) for '{search_keyword}' on {count} records. Errors: {deserialization_errors}"
        )
        session['statistics'] = {
            'query': f"Average {human_readable_field} for '{search_keyword}'", 'count': count,
            'true_average': f"{true_average:.2f}", 'dp_average': f"{dp_average:.2f}",
            'epsilon': epsilon, 'deserialization_errors': deserialization_errors
        }
        flash("Conditional statistical analysis complete!", "success")

    except Exception as e:
        flash(f"An error occurred during conditional analysis: {e}", "danger")
        traceback.print_exc()

    return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect


@admin_stats_bp.route('/age_by_diagnosis', methods=['POST'])
def run_age_by_diagnosis_statistics():
    """Performs secure avg age calculation based on diagnosis via SSE."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if not PHE_PRIVATE_KEY:
         flash("PHE Private Key not loaded. Cannot perform statistics.", "danger")
         return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

    try:
        search_keyword = request.form.get('search_keyword_age')
        if not search_keyword:
            flash("Search keyword for diagnosis is required.", "warning")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        search_token = generate_sse_token(search_keyword)
        conn = get_db_connection()
        patient_ids_rows = conn.execute(
            """SELECT DISTINCT mr.patient_user_id FROM search_index si
               JOIN medical_records mr ON si.record_id = mr.record_id
               WHERE si.keyword_token = ?""", (search_token,)
        ).fetchall()

        if not patient_ids_rows:
            flash(f"No records found matching diagnosis '{search_keyword}'.", "info")
            conn.close(); return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        patient_ids = [row['patient_user_id'] for row in patient_ids_rows]
        placeholders = ','.join('?' for _ in patient_ids)
        age_rows = conn.execute(
            f"SELECT phe_age FROM patient_profile WHERE user_id IN ({placeholders}) AND phe_age IS NOT NULL", patient_ids
        ).fetchall()
        conn.close()

        if not age_rows:
            flash(f"Patients found for '{search_keyword}', but none have age data.", "info")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        encrypted_ages = []
        deserialization_errors = 0
        for row in age_rows:
            try:
                encrypted_num = phe_decrypt(PHE_PRIVATE_KEY, row['phe_age'], deserialize_only=True)
                if encrypted_num: encrypted_ages.append(encrypted_num)
                else: deserialization_errors += 1
            except Exception: deserialization_errors += 1

        if not encrypted_ages:
            flash(f"Failed to deserialize age data for matching patients.", "danger")
            return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

        count = len(encrypted_ages)
        encrypted_sum = sum(encrypted_ages)
        plain_sum = phe_decrypt(PHE_PRIVATE_KEY, encrypted_sum)

        if plain_sum is None: raise Exception("PHE decryption of final age sum failed.")

        true_average = plain_sum / count
        data_bounds = [0, 120]; epsilon = 0.5 # Bounds for age
        sensitivity = (data_bounds[1] - data_bounds[0]) / count if count > 0 else 0
        scale = sensitivity / epsilon if epsilon > 0 else float('inf')
        noise = np.random.laplace(loc=0.0, scale=scale if scale != float('inf') else 0, size=1)[0]
        dp_average = np.clip(true_average + noise, data_bounds[0], data_bounds[1])

        blockchain.log_action_to_blockchain(
            user_id=session['user_id'], action="RUN_AGE_BY_DIAGNOSIS_STATISTICS",
            details=f"Calculated DP avg Age (e={epsilon}) for diagnosis '{search_keyword}' on {count} patients. Errors: {deserialization_errors}"
        )
        session['statistics'] = {
            'query': f"Average Age for '{search_keyword}'", 'count': count,
            'true_average': f"{true_average:.2f}", 'dp_average': f"{dp_average:.2f}",
            'epsilon': epsilon, 'deserialization_errors': deserialization_errors
        }
        flash("Average age by diagnosis analysis complete!", "success")

    except Exception as e:
        flash(f"An error occurred during age analysis: {e}", "danger")
        traceback.print_exc()

    return redirect(url_for('admin_logs.admin_dashboard_tiles')) # Corrected redirect

