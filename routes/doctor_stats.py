# --- NEW FILE: routes/doctor_stats.py ---

from flask import (
    Blueprint, request, redirect, url_for, session, flash
)
import traceback

# --- Project Imports ---
from database import get_db_connection
from crypto import get_phe_keys, phe_decrypt, generate_sse_token
import blockchain

# Define the Blueprint for doctor statistics
doctor_stats_bp = Blueprint('doctor_stats', __name__)

# --- Load PHE Private Key ---
try:
    _, PHE_PRIVATE_KEY = get_phe_keys() # Load only private key needed for decryption
except Exception as e:
    print(f"CRITICAL ERROR: Could not load PHE private key in doctor_stats blueprint: {e}")
    PHE_PRIVATE_KEY = None # Handle gracefully


# --- Doctor Stats Routes (Moved from doctor.py) ---

@doctor_stats_bp.route('/stats_bp_heart_patients', methods=['POST'])
def doctor_stats_bp_heart_patients():
    """Calculates average BP for patients diagnosed with 'Heart Disease'."""
    if 'user_id' not in session or session.get('role') != 'doctor':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if not PHE_PRIVATE_KEY:
         flash("PHE keys not loaded. Cannot perform statistics.", "warning")
         return redirect(url_for('dashboard', view='insights'))

    search_keyword = "Heart Disease" # Hardcoded for this specific stat
    stat_result_text = f"Could not calculate average BP for '{search_keyword}' patients." # Default
    count = 0
    conn = None # Initialize conn

    try:
        search_token = generate_sse_token(search_keyword)
        conn = get_db_connection()

        # Find record_ids matching the diagnosis
        record_ids_rows = conn.execute(
            "SELECT record_id FROM search_index WHERE keyword_token = ?", (search_token,)
        ).fetchall()

        if record_ids_rows:
            record_ids = [row['record_id'] for row in record_ids_rows]
            placeholders = ','.join('?' for _ in record_ids)

            # Fetch encrypted BP values for those records
            bp_query = f"""SELECT phe_systolic, phe_diastolic FROM medical_records
                           WHERE record_id IN ({placeholders})
                           AND phe_systolic IS NOT NULL AND phe_diastolic IS NOT NULL"""
            bp_rows = conn.execute(bp_query, record_ids).fetchall()

            if bp_rows:
                encrypted_systolics = []
                encrypted_diastolics = []
                deserialization_errors = 0
                for row in bp_rows:
                    try:
                        # Decrypt returns the EncryptedNumber object when deserialize_only=True
                        enc_sys = phe_decrypt(PHE_PRIVATE_KEY, row['phe_systolic'], deserialize_only=True)
                        enc_dia = phe_decrypt(PHE_PRIVATE_KEY, row['phe_diastolic'], deserialize_only=True)
                        if enc_sys and enc_dia:
                            encrypted_systolics.append(enc_sys)
                            encrypted_diastolics.append(enc_dia)
                        else:
                             deserialization_errors += 1
                             print(f"Failed to deserialize BP pair for a record.") # More specific log
                    except Exception as e:
                        print(f"BP Deserialization error during loop: {e}")
                        deserialization_errors += 1

                if encrypted_systolics: # Check if we have valid pairs
                    count = len(encrypted_systolics)
                    # Sum the EncryptedNumber objects directly
                    sum_enc_sys = sum(encrypted_systolics)
                    sum_enc_dia = sum(encrypted_diastolics)

                    # Decrypt the final sums
                    sum_sys_decrypted = phe_decrypt(PHE_PRIVATE_KEY, sum_enc_sys)
                    sum_dia_decrypted = phe_decrypt(PHE_PRIVATE_KEY, sum_enc_dia)


                    if sum_sys_decrypted is not None and sum_dia_decrypted is not None:
                        avg_sys = sum_sys_decrypted / count
                        avg_dia = sum_dia_decrypted / count
                        # Simple average, no DP for doctor view yet
                        stat_result_text = f"Average BP for '{search_keyword}' ({count} records): {avg_sys:.1f} / {avg_dia:.1f} mmHg (Deserialization Errors: {deserialization_errors})"
                    else:
                         stat_result_text = f"PHE decryption failed after summing BP for {count} records."
                else:
                    stat_result_text = f"Found {len(record_ids)} records for '{search_keyword}', but failed to deserialize valid BP pairs (Errors: {deserialization_errors})."
            else:
                stat_result_text = f"Found {len(record_ids)} records for '{search_keyword}', but none had valid & non-null PHE BP data."
        else:
            stat_result_text = f"No records found for diagnosis '{search_keyword}'."


        blockchain.log_action_to_blockchain(
            user_id=session['user_id'],
            action=blockchain.ACTION_DOCTOR_RUN_BP_STATS, # Use constant from blockchain.py
            details=f"Calculated BP stats for '{search_keyword}'. Result: {stat_result_text}"
        )

    except Exception as e:
        stat_result_text = f"Error during BP statistics: {e}"
        flash(stat_result_text, "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close() # Ensure connection is closed

    session['stats_results'] = {
        'query': f"Avg BP for '{search_keyword}' Patients",
        'result': stat_result_text
    }
    session.modified = True
    return redirect(url_for('dashboard', view='insights'))


@doctor_stats_bp.route('/stats_pulse_smoking', methods=['POST'])
def doctor_stats_pulse_smoking():
    """Calculates average pulse (heart rate) based on smoking status."""
    if 'user_id' not in session or session.get('role') != 'doctor':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if not PHE_PRIVATE_KEY:
         flash("PHE keys not loaded. Cannot perform statistics.", "warning")
         return redirect(url_for('dashboard', view='insights'))

    smoking_status_filter = request.form.get('smoking_status_filter')
    if not smoking_status_filter:
        flash("Please select a smoking status.", "warning")
        return redirect(url_for('dashboard', view='insights'))

    stat_result_text = f"Could not calculate average pulse for status '{smoking_status_filter}'." # Default
    count = 0
    conn = None # Initialize conn

    try:
        status_token = generate_sse_token(smoking_status_filter)
        conn = get_db_connection()

        # Find patient_ids matching the smoking status token
        patient_ids_rows = conn.execute(
            "SELECT user_id FROM patient_profile_index WHERE keyword_token = ?", (status_token,)
        ).fetchall()

        if patient_ids_rows:
            patient_ids = [row['user_id'] for row in patient_ids_rows]
            placeholders = ','.join('?' for _ in patient_ids)

            # Fetch encrypted heart rates for records CREATED FOR these patients
            hr_query = f"""SELECT phe_heart_rate FROM medical_records
                           WHERE patient_user_id IN ({placeholders})
                           AND phe_heart_rate IS NOT NULL"""
            hr_rows = conn.execute(hr_query, patient_ids).fetchall()

            if hr_rows:
                encrypted_hrs = []
                deserialization_errors = 0
                for row in hr_rows:
                    try:
                        # Decrypt only to deserialize
                        enc_hr = phe_decrypt(PHE_PRIVATE_KEY, row['phe_heart_rate'], deserialize_only=True)
                        if enc_hr:
                             encrypted_hrs.append(enc_hr)
                        else:
                             deserialization_errors += 1
                             print("Failed to deserialize HR for a record.")
                    except Exception as e:
                        print(f"HR Deserialization error during loop: {e}")
                        deserialization_errors += 1

                if encrypted_hrs:
                    count = len(encrypted_hrs)
                    # Sum EncryptedNumber objects
                    sum_enc_hr = sum(encrypted_hrs)
                    # Decrypt the final sum
                    sum_hr_decrypted = phe_decrypt(PHE_PRIVATE_KEY, sum_enc_hr)

                    if sum_hr_decrypted is not None:
                        avg_hr = sum_hr_decrypted / count
                        # Simple average, no DP
                        stat_result_text = f"Average Pulse for '{smoking_status_filter}' ({count} records): {avg_hr:.1f} bpm (Deserialization Errors: {deserialization_errors})"
                    else:
                        stat_result_text = f"PHE decryption failed after summing HR for {count} records."
                else:
                    stat_result_text = f"Found {len(patient_ids)} patients with status '{smoking_status_filter}', but failed to deserialize valid HR data (Errors: {deserialization_errors})."
            else:
                 stat_result_text = f"Found {len(patient_ids)} patients with status '{smoking_status_filter}', but none had valid & non-null PHE HR data recorded."
        else:
            stat_result_text = f"No patients found with smoking status '{smoking_status_filter}'."


        blockchain.log_action_to_blockchain(
            user_id=session['user_id'],
            action=blockchain.ACTION_DOCTOR_RUN_PULSE_STATS, # Use constant from blockchain.py
            details=f"Calculated Pulse stats for '{smoking_status_filter}'. Result: {stat_result_text}"
        )

    except Exception as e:
        stat_result_text = f"Error during Pulse statistics: {e}"
        flash(stat_result_text, "danger")
        traceback.print_exc()
    finally:
        if conn: conn.close() # Ensure connection is closed

    session['stats_results'] = {
        'query': f"Avg Pulse for '{smoking_status_filter}'",
        'result': stat_result_text
    }
    session.modified = True
    return redirect(url_for('dashboard', view='insights'))
