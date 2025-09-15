from flask import Blueprint, render_template, redirect, url_for, session, flash, json, request
import traceback # Import traceback

# CORRECTED: Use absolute imports
from database import get_db_connection
from crypto import decrypt_record_aes, verify_signature # Added verify_signature

# Define the Blueprint
# Point to parent templates folder
patient_bp = Blueprint('patient', __name__, template_folder='../templates')

# --- Function to Render Dashboard (called by main app.py) ---

def render_patient_dashboard():
    """Fetches data and renders the patient dashboard (Tiles or Prescriptions List)."""
    if 'user_id' not in session or session.get('role') != 'patient':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login')) # Use main login route

    user_id = session['user_id']
    # Attributes might still be needed for the header/profile popup
    user_attributes = session.get('attributes', {}).copy()

    view = request.args.get('view', 'tiles') # Default to tiles view
    prescription_list_metadata = [] # Renamed from decrypted_records
    patient_profile_info = None # For personal info tile

    conn = get_db_connection()
    try:
        # Fetch patient profile info for the 'Personal Info' tile
        patient_profile_raw = conn.execute(
            "SELECT full_name, phe_age, smoking_status FROM patient_profile WHERE user_id = ?",
            (user_id,)
        ).fetchone()
        if patient_profile_raw:
            patient_profile_info = dict(patient_profile_raw)
            # Decrypt age here later if needed

        # Fetch prescription METADATA only if viewing prescriptions list
        if view == 'prescriptions':
            my_records_raw = conn.execute(
                """SELECT mr.record_id, mr.created_at,
                   ua.attribute_value as doctor_name
                   FROM medical_records mr
                   LEFT JOIN user_attributes ua ON mr.created_by_user_id = ua.user_id AND ua.attribute_name = 'full_name'
                   WHERE mr.patient_user_id = ? AND mr.record_type = 'prescription'
                   ORDER BY mr.created_at DESC""",
                (user_id,)
            ).fetchall()

            # --- REMOVED DECRYPTION LOOP ---
            # Simply format the metadata for the list
            if my_records_raw:
                prescription_list_metadata = [
                    {
                        'record_id': record['record_id'],
                        'created_at': record['created_at'],
                        'doctor_name': record['doctor_name'] or 'Unknown Doctor'
                        # No decryption status needed here anymore
                    }
                    for record in my_records_raw
                ]
            # --- END REMOVAL ---

    except Exception as db_e:
         flash(f"Error fetching patient data: {db_e}", "danger")
         print(f"Database error in render_patient_dashboard: {db_e}")
         traceback.print_exc() # Print traceback
    finally:
        if conn:
            conn.close()

    # User data for the template header
    user_header_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role')
    }

    return render_template('patient_dashboard.html',
                           user=user_header_data,
                           view=view,
                           records=prescription_list_metadata, # Pass metadata list
                           profile=patient_profile_info)

# --- Patient Specific Routes (if any needed later) ---
# @patient_bp.route('/view_my_details')
# def view_my_details():
#    ...

