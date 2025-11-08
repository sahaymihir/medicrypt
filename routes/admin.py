from flask import (
    Blueprint, render_template, request, redirect, url_for, session, flash,
    send_file # Added for file download
)
import pickle
import numpy as np
from phe import paillier
import traceback
import io # Added for file download
import os # Added for path operations

# CORRECTED: Use absolute imports from the project root
from database import get_db_connection
from auth import register_user, is_password_strong
from crypto import get_phe_keys, phe_decrypt, generate_sse_token
import blockchain # Corrected import assuming blockchain.py is at the root

# Import DP library safely
try:
    from diffprivlib.tools.mean import mean as dp_mean
except ImportError:
    print("Warning: diffprivlib not found. Statistics will not be differentially private.")
    # Fallback non-private mean function
    def dp_mean(data, epsilon=None, range=None): # Accept epsilon/range but ignore
        if not data: return 0
        valid_data = [x for x in data if x is not None] # Filter out None values just in case
        if not valid_data: return 0
        return np.mean(valid_data)


# Define the Blueprint
admin_bp = Blueprint('admin', __name__, template_folder='../templates') # Point to parent

# --- Helper - Load PHE keys only once ---
try:
    _, PHE_PRIVATE_KEY = get_phe_keys()
except Exception as e:
    print(f"CRITICAL ERROR: Could not load PHE keys in admin blueprint: {e}")
    PHE_PRIVATE_KEY = None # Handle gracefully if keys are missing

# --- Functions to Render Dashboards (called by main app.py) ---

def render_admin_dashboard():
    """Fetches data and renders the admin dashboard."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    # Determine view (tiles or logs)
    view = request.args.get('view', 'tiles') # Default to tiles
    role_filter = request.args.get('role_filter', '') # Get role filter

    logs = []
    if view == 'logs':
        conn = get_db_connection()
        try:
            # --- UPDATED QUERY: Join to get role, add filtering ---
            base_query = """
                SELECT b.*, r.role_name
                FROM blockchain_audit_log b
                LEFT JOIN users u ON b.user_id = u.user_id
                LEFT JOIN roles r ON u.role_id = r.role_id
            """
            params = []
            if role_filter:
                base_query += " WHERE r.role_name = ?"
                params.append(role_filter)

            base_query += " ORDER BY b.log_id DESC LIMIT 50" # Limit logs fetched

            logs = conn.execute(base_query, params).fetchall()
            # --- END UPDATE ---
        except Exception as e:
            flash(f"Error fetching logs: {e}", "danger")
            print(f"Error fetching logs: {e}")
            traceback.print_exc()
        finally:
            if conn:
                conn.close()


    # Prepare data for the template
    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role')
        # Add other user details if needed by the template header
    }

    template_data = {
        'user': user_data,
        'view': view,
        'logs': logs,
        'role_filter': role_filter # Pass filter back to template
    }

    return render_template('admin_dashboard.html', **template_data)


# --- Admin Specific Routes ---

@admin_bp.route('/admin_create_user_form')
def admin_create_user_form():
    """Shows the admin page for creating a new user."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('dashboard')) # Redirect to main dashboard

    # Prepare user data for template header
    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role')
    }
    return render_template('admin_create_user_form.html', user=user_data)


@admin_bp.route('/admin_create_user', methods=['POST'])
def admin_create_user():
    """Handles the creation of a new user by an admin."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('dashboard'))

    try:
        full_name = request.form['full_name']
        password = request.form['password'].strip()
        role_name = request.form['role_name']
        age_str = request.form.get('age') # Get age if provided (for patient)

        if not all([full_name, password, role_name]):
            flash("Full Name, Password, and Role are required.", "warning")
            return redirect(url_for('admin.admin_create_user_form'))

        # Check password strength
        is_strong, error_msg = is_password_strong(password)
        if not is_strong:
            flash(f"Password is not strong enough: {error_msg}", 'danger')
            return redirect(url_for('admin.admin_create_user_form'))

        # Prepare profile data
        profile_data = {
            'department': request.form.get('department'),
            'specialty': request.form.get('specialty'),
            'hospital_id': request.form.get('hospital_id'),
            'pharmacy_name': request.form.get('pharmacy_name'),
            'license_number': request.form.get('license_number'),
            'contact_email': request.form.get('contact_email')
        }

        # Convert age to int if provided and valid
        age = None
        if role_name == 'patient' and age_str and age_str.isdigit():
            age = int(age_str)
        elif role_name == 'patient' and age_str:
            flash("Invalid age provided for patient.", "warning")
            return redirect(url_for('admin.admin_create_user_form'))


        # Call register_user (now returns private key)
        user_id, new_username, private_key_pem = register_user(
            full_name, password, role_name, profile_data, age=age
        )

        if user_id and private_key_pem:
            flash(f"Successfully created user '{full_name}' ({new_username}).", "success")
            blockchain.log_action_to_blockchain(
                user_id=session['user_id'],
                action='ADMIN_CREATE_USER',
                details=f"Admin created user {new_username} ({role_name})"
            )
            # Store key temporarily to prompt download
            session['download_key_pem'] = private_key_pem.decode('utf-8')
            session['download_key_username'] = new_username
            return redirect(url_for('admin.admin_prompt_download_key'))
        else:
            flash("Failed to create user. Username may be taken or data is invalid.", "danger")

    except Exception as e:
        flash(f"An error occurred during user creation: {e}", "danger")
        traceback.print_exc()

    return redirect(url_for('admin.admin_create_user_form')) # Redirect back to form on failure


@admin_bp.route('/admin_download_key')
def admin_prompt_download_key():
    """Displays page prompting the user to download their key."""
    if 'download_key_pem' not in session or 'download_key_username' not in session:
        flash("No key available for download or session expired.", "warning")
        return redirect(url_for('dashboard')) # Redirect to main dashboard

    username = session['download_key_username']
     # Prepare user data for template header
    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role')
    }
    return render_template('admin_download_key.html', key_username=username, user=user_data)


@admin_bp.route('/admin_get_key')
def admin_get_key():
    """Provides the private key as a file download."""
    if 'download_key_pem' not in session or 'download_key_username' not in session:
        flash("No key available for download or session expired.", "warning")
        return redirect(url_for('dashboard'))

    key_pem = session.pop('download_key_pem') # Remove key after retrieval
    username = session.pop('download_key_username')

    # Sanitize username for filename
    safe_filename = username.replace('@', '_at_').replace('.', '_dot_')
    filename = f"{safe_filename}_private_key.pem"

    return send_file(
        io.BytesIO(key_pem.encode('utf-8')),
        mimetype='application/x-pem-file',
        as_attachment=True,
        download_name=filename
    )


# --- Statistics Routes (No significant changes needed here for now) ---

# This route calculates overall average heart rate
@admin_bp.route('/admin_statistics', methods=['POST'])
def admin_statistics():
    """Performs secure, differentially private statistics (e.g., avg heart rate)."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('dashboard'))

    if not PHE_PRIVATE_KEY:
         flash("PHE Private Key not loaded. Cannot perform statistics.", "danger")
         return redirect(url_for('dashboard'))

    try:
        conn = get_db_connection()
        # Fetch only heart rate
        rows = conn.execute("SELECT phe_heart_rate FROM medical_records WHERE phe_heart_rate IS NOT NULL").fetchall()
        conn.close()

        if not rows:
            flash("No heart rate data found to analyze.", "warning")
            return redirect(url_for('dashboard'))

        encrypted_hrs = []
        deserialization_errors = 0
        for row in rows:
            try:
                # Use phe_decrypt helper for robust deserialization
                encrypted_num = phe_decrypt(PHE_PRIVATE_KEY, row['phe_heart_rate'], deserialize_only=True)
                if encrypted_num:
                    encrypted_hrs.append(encrypted_num)
                else:
                     deserialization_errors += 1
            except Exception as e:
                print(f"Could not deserialize PHE heart rate data: {e}")
                deserialization_errors += 1

        if not encrypted_hrs:
            flash(f"Found {len(rows)} heart rate points, but failed to deserialize any valid ones.", "danger")
            return redirect(url_for('dashboard'))

        count = len(encrypted_hrs)
        print(f"Calculating sum on {count} encrypted heart rates...")
        encrypted_sum = sum(encrypted_hrs)
        plain_sum = phe_decrypt(PHE_PRIVATE_KEY, encrypted_sum) # Decrypt final sum

        if plain_sum is None:
            print(f"PHE decryption failed. Encrypted sum type: {type(encrypted_sum)}")
            raise Exception("PHE decryption of final sum failed.")

        true_average = plain_sum / count

        # Apply Differential Privacy
        data_bounds = [0, 250] # Reasonable bounds for heart rate
        epsilon = 0.5

        # Calculate DP average using the library function (or fallback)
        # We need the individual decrypted values ONLY for the library function.
        # For simplicity with PHE, we'll add noise manually as before.
        # dp_average = dp_mean(decrypted_values, epsilon=epsilon, range=data_bounds)
        sensitivity = (data_bounds[1] - data_bounds[0]) / count if count > 0 else 0
        scale = sensitivity / epsilon if epsilon > 0 else float('inf')
        noise = np.random.laplace(loc=0.0, scale=scale if scale != float('inf') else 0, size=1)[0]
        dp_average = np.clip(true_average + noise, data_bounds[0], data_bounds[1])


        blockchain.log_action_to_blockchain(
            user_id=session['user_id'],
            action="RUN_STATISTICS",
            details=f"Calculated DP avg HR (e={epsilon}) on {count} records. Errors: {deserialization_errors}"
        )

        session['statistics'] = {
            'query': 'Average Heart Rate (All Patients)', # Add query title
            'count': count,
            'true_average': f"{true_average:.2f}",
            'dp_average': f"{dp_average:.2f}",
            'epsilon': epsilon,
            'deserialization_errors': deserialization_errors
        }
        flash("Statistical analysis complete!", "success")

    except Exception as e:
        print(f"Error during statistics: {e}")
        flash(f"An error occurred during statistical analysis: {e}", "danger")
        traceback.print_exc()

    return redirect(url_for('dashboard')) # Redirect to main dashboard

# This route calculates average for a field based on diagnosis search
@admin_bp.route('/admin_conditional_statistics', methods=['POST'])
def admin_conditional_statistics():
    """Performs secure statistics on a subset based on SSE keyword search."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if not PHE_PRIVATE_KEY:
         flash("PHE Private Key not loaded. Cannot perform statistics.", "danger")
         return redirect(url_for('dashboard'))

    try:
        # Get form data
        statistic_field = request.form.get('statistic_field') # e.g., 'phe_weight'
        search_keyword = request.form.get('search_keyword')  # e.g., 'heart disease'

        if not statistic_field or not search_keyword:
            flash("Statistic field and search keyword are required.", "warning")
            return redirect(url_for('dashboard'))

        # Whitelist allowed column names
        allowed_fields = {
            # Field name in DB : User-friendly name
            'phe_weight': 'Weight (kg)',
            'phe_height': 'Height (cm)',
            'phe_heart_rate': 'Heart Rate (bpm)'
        }
        if statistic_field not in allowed_fields:
            flash("Invalid statistic field selected.", "danger")
            return redirect(url_for('dashboard'))

        human_readable_field = allowed_fields[statistic_field]

        # 1. Generate SSE token
        search_token = generate_sse_token(search_keyword)
        print(f"Searching for token: {search_token} (keyword: '{search_keyword}')")

        conn = get_db_connection()

        # 2. Find matching record_ids
        record_ids_rows = conn.execute(
            "SELECT record_id FROM search_index WHERE keyword_token = ?", (search_token,)
        ).fetchall()

        if not record_ids_rows:
            flash(f"No records found matching the diagnosis '{search_keyword}'.", "info")
            conn.close()
            return redirect(url_for('dashboard'))

        record_ids = [row['record_id'] for row in record_ids_rows]
        placeholders = ','.join('?' for _ in record_ids)
        print(f"Found {len(record_ids)} records matching token.")

        # 3. Fetch the specific PHE data for those records
        # Use f-string safely ONLY with the whitelisted column name
        query = f"SELECT {statistic_field} FROM medical_records WHERE record_id IN ({placeholders}) AND {statistic_field} IS NOT NULL"
        rows = conn.execute(query, record_ids).fetchall()
        conn.close()

        if not rows:
            flash(f"Records found for '{search_keyword}', but none have {human_readable_field} data.", "info")
            return redirect(url_for('dashboard'))

        print(f"Found {len(rows)} records with PHE data for field '{statistic_field}'.")

        # 4. Perform aggregation (same logic)
        encrypted_values = []
        deserialization_errors = 0
        for row in rows:
            try:
                 # Use phe_decrypt helper for robust deserialization
                encrypted_num = phe_decrypt(PHE_PRIVATE_KEY, row[0], deserialize_only=True)
                if encrypted_num:
                    encrypted_values.append(encrypted_num)
                else:
                    deserialization_errors += 1 # phe_decrypt returned None
            except Exception as e:
                print(f"Could not deserialize PHE conditional data: {e}")
                deserialization_errors += 1

        if not encrypted_values:
            flash(f"Failed to deserialize any {human_readable_field} data for the matching records.", "danger")
            return redirect(url_for('dashboard'))

        count = len(encrypted_values)
        encrypted_sum = sum(encrypted_values)
        plain_sum = phe_decrypt(PHE_PRIVATE_KEY, encrypted_sum) # Decrypt final sum

        if plain_sum is None:
            raise Exception("PHE decryption of final sum failed.")

        true_average = plain_sum / count

        # 5. Apply Differential Privacy (Manual noise addition)
        data_bounds = [0, 300] # Adjust bounds based on field if needed
        epsilon = 0.5
        sensitivity = (data_bounds[1] - data_bounds[0]) / count if count > 0 else 0
        scale = sensitivity / epsilon if epsilon > 0 else float('inf')
        noise = np.random.laplace(loc=0.0, scale=scale if scale != float('inf') else 0, size=1)[0]
        dp_average = np.clip(true_average + noise, data_bounds[0], data_bounds[1])


        blockchain.log_action_to_blockchain(
            user_id=session['user_id'],
            action="RUN_CONDITIONAL_STATISTICS",
            details=f"Calculated DP avg {human_readable_field} (e={epsilon}) for '{search_keyword}' on {count} records. Errors: {deserialization_errors}"
        )

        session['statistics'] = {
            'query': f"Average {human_readable_field} for '{search_keyword}'",
            'count': count,
            'true_average': f"{true_average:.2f}",
            'dp_average': f"{dp_average:.2f}",
            'epsilon': epsilon,
            'deserialization_errors': deserialization_errors
        }
        flash("Conditional statistical analysis complete!", "success")

    except Exception as e:
        flash(f"An error occurred during conditional analysis: {e}", "danger")
        traceback.print_exc()

    return redirect(url_for('dashboard'))


# This route calculates average age based on diagnosis search (Secure Join)
@admin_bp.route('/admin_age_by_diagnosis', methods=['POST'])
def admin_age_by_diagnosis():
    """Performs secure avg age calculation based on diagnosis via SSE."""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if not PHE_PRIVATE_KEY:
         flash("PHE Private Key not loaded. Cannot perform statistics.", "danger")
         return redirect(url_for('dashboard'))

    try:
        search_keyword = request.form.get('search_keyword_age')
        if not search_keyword:
            flash("Search keyword for diagnosis is required.", "warning")
            return redirect(url_for('dashboard'))

        # 1. Generate SSE token
        search_token = generate_sse_token(search_keyword)
        print(f"Searching for age using token: {search_token} (keyword: '{search_keyword}')")

        conn = get_db_connection()

        # 2. Find matching record_ids and associated patient_user_ids
        patient_ids_rows = conn.execute(
            """SELECT DISTINCT mr.patient_user_id
               FROM search_index si
               JOIN medical_records mr ON si.record_id = mr.record_id
               WHERE si.keyword_token = ?""",
            (search_token,)
        ).fetchall()

        if not patient_ids_rows:
            flash(f"No records found matching the diagnosis '{search_keyword}'.", "info")
            conn.close()
            return redirect(url_for('dashboard'))

        patient_ids = [row['patient_user_id'] for row in patient_ids_rows]
        placeholders = ','.join('?' for _ in patient_ids)
        print(f"Found {len(patient_ids)} distinct patients matching token.")

        # 3. Fetch the PHE Age data for those specific patients
        age_rows = conn.execute(
            f"SELECT phe_age FROM patient_profile WHERE user_id IN ({placeholders}) AND phe_age IS NOT NULL",
            patient_ids
        ).fetchall()
        conn.close()

        if not age_rows:
            flash(f"Patients found for '{search_keyword}', but none have age data.", "info")
            return redirect(url_for('dashboard'))

        print(f"Found {len(age_rows)} patients with PHE age data.")

        # 4. Perform aggregation (same logic)
        encrypted_ages = []
        deserialization_errors = 0
        for row in age_rows:
            try:
                # Use phe_decrypt helper
                encrypted_num = phe_decrypt(PHE_PRIVATE_KEY, row['phe_age'], deserialize_only=True)
                if encrypted_num:
                    encrypted_ages.append(encrypted_num)
                else:
                    deserialization_errors += 1
            except Exception as e:
                print(f"Could not deserialize PHE age data: {e}")
                deserialization_errors += 1

        if not encrypted_ages:
            flash(f"Failed to deserialize any age data for the matching patients.", "danger")
            return redirect(url_for('dashboard'))

        count = len(encrypted_ages)
        encrypted_sum = sum(encrypted_ages)
        plain_sum = phe_decrypt(PHE_PRIVATE_KEY, encrypted_sum)

        if plain_sum is None:
            raise Exception("PHE decryption of final age sum failed.")

        true_average = plain_sum / count

        # 5. Apply Differential Privacy
        data_bounds = [0, 120] # Bounds for age
        epsilon = 0.5
        sensitivity = (data_bounds[1] - data_bounds[0]) / count if count > 0 else 0
        scale = sensitivity / epsilon if epsilon > 0 else float('inf')
        noise = np.random.laplace(loc=0.0, scale=scale if scale != float('inf') else 0, size=1)[0]
        dp_average = np.clip(true_average + noise, data_bounds[0], data_bounds[1])

        blockchain.log_action_to_blockchain(
            user_id=session['user_id'],
            action="RUN_AGE_BY_DIAGNOSIS_STATISTICS",
            details=f"Calculated DP avg Age (e={epsilon}) for diagnosis '{search_keyword}' on {count} patients. Errors: {deserialization_errors}"
        )

        session['statistics'] = {
            'query': f"Average Age for '{search_keyword}'",
            'count': count,
            'true_average': f"{true_average:.2f}",
            'dp_average': f"{dp_average:.2f}",
            'epsilon': epsilon,
            'deserialization_errors': deserialization_errors
        }
        flash("Average age by diagnosis analysis complete!", "success")

    except Exception as e:
        flash(f"An error occurred during age analysis: {e}", "danger")
        traceback.print_exc()

    return redirect(url_for('dashboard'))

