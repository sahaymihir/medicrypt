from flask import Blueprint, render_template, redirect, url_for, session, flash, json, request
import traceback # Import traceback
import binascii # For handling hex errors

# CORRECTED: Use absolute imports
from database import get_db_connection
from crypto import decrypt_record_aes, verify_signature
# Assuming blockchain.py is at the root
import blockchain # Import blockchain for logging dispensing action

# Define the Blueprint
pharmacist_bp = Blueprint('pharmacist', __name__, template_folder='../templates') # Point to parent

# --- Function to Render Dashboard (Handles different views) ---

def render_pharmacist_dashboard():
    """Fetches data and renders the appropriate pharmacist dashboard view (tiles, verify, log)."""
    if 'user_id' not in session or session.get('role') != 'pharmacist':
         flash("Unauthorized access.", "danger")
         return redirect(url_for('login')) # Use main login route

    view = request.args.get('view', 'tiles') # Default to tiles
    user_id = session['user_id']
    user_attributes = session.get('attributes', {})

    # --- SAFE USER DATA CONSTRUCTION for header ---
    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role'),
        'attributes': user_attributes
    }
    # --- END SAFE CONSTRUCTION ---

    conn = None
    template_data = {
        'user': user_data,
        'view': view,
        'prescriptions': [], # For verify_prescription list view
        'dispensing_log': [] # For log view
    }

    try:
        conn = get_db_connection()

        if view == 'verify_prescription':
            # Fetch basic info for prescriptions accessible by the pharmacist
            # DO NOT decrypt or verify here
            accessible_records_raw = conn.execute(
                """SELECT mr.record_id, mr.patient_user_id, mr.created_at,
                       pp.full_name as patient_name
                 FROM medical_records mr
                 LEFT JOIN patient_profile pp ON mr.patient_user_id = pp.user_id
                 WHERE mr.record_type = 'prescription'
                 ORDER BY mr.created_at DESC""" # Order might be helpful
            ).fetchall()

            # Simple policy check simulation (can be improved)
            # In a real ABE system, this check might be implicit in the fetch
            accessible_prescriptions = []
            if accessible_records_raw:
                policy_placeholder = "role:pharmacist" # Simplified check
                for record in accessible_records_raw:
                    # TODO: Add a more robust policy check if needed before showing the link
                    # For now, assume pharmacists might have access to all prescriptions
                    # A better check would involve fetching policy_str and evaluating it partially
                     accessible_prescriptions.append({
                        'record_id': record['record_id'],
                        'patient_user_id': record['patient_user_id'],
                        'patient_name': record['patient_name'] or 'Unknown Patient',
                        'created_at': record['created_at']
                     })

            template_data['prescriptions'] = accessible_prescriptions

        elif view == 'dispensing_log':
            # Fetch dispensing events from blockchain for the current pharmacist
            log_entries_raw = conn.execute(
                """SELECT log.record_id, log.timestamp, mr.patient_user_id, pp.full_name as patient_name
                   FROM blockchain_audit_log log
                   JOIN medical_records mr ON log.record_id = mr.record_id
                   LEFT JOIN patient_profile pp ON mr.patient_user_id = pp.user_id
                   WHERE log.user_id = ? AND log.action = ?
                   ORDER BY log.timestamp DESC""",
                (user_id, blockchain.ACTION_PHARMACIST_DISPENSE)
            ).fetchall()
            template_data['dispensing_log'] = [dict(row) for row in log_entries_raw] if log_entries_raw else []

    except Exception as e:
        flash(f"Error loading pharmacist dashboard: {e}", "danger")
        print("--- ERROR rendering pharmacist dashboard ---")
        traceback.print_exc()
        template_data['view'] = 'tiles' # Fallback to tiles view on error
    finally:
        if conn:
            conn.close()

    # Use the main dashboard template which decides view based on 'view' variable
    return render_template('pharmacist_dashboard.html', **template_data)


# --- NEW Route for Viewing/Verifying a Single Prescription ---

@pharmacist_bp.route('/verify_details/<record_id>')
def pharmacist_verify_details(record_id):
    """Decrypts, verifies, and displays limited details for a single prescription."""
    if 'user_id' not in session or session.get('role') != 'pharmacist':
         flash("Unauthorized access.", "danger")
         return redirect(url_for('login'))

    user_attributes = session.get('attributes', {})
    conn = None
    prescription_details = None
    is_valid_signature = False
    is_dispensed = False
    error_message = None

    try:
        conn = get_db_connection()
        # Fetch the specific record including encrypted data and signer info
        record_raw = conn.execute(
            """SELECT mr.record_id, mr.patient_user_id, mr.created_at, mr.policy_str,
                      mr.encrypted_data, mr.created_by_user_id,
                      pp.full_name as patient_name, signer.public_key AS signer_public_key
               FROM medical_records mr
               LEFT JOIN patient_profile pp ON mr.patient_user_id = pp.user_id
               LEFT JOIN users signer ON mr.created_by_user_id = signer.user_id
               WHERE mr.record_id = ? AND mr.record_type = 'prescription'""",
            (record_id,)
        ).fetchone()

        if not record_raw:
            flash("Prescription record not found.", "danger")
            return redirect(url_for('dashboard', view='verify_prescription'))

        # Check essential data
        if not record_raw['encrypted_data'] or not isinstance(record_raw['encrypted_data'], bytes) or not record_raw['policy_str'] or not record_raw['created_by_user_id'] or not record_raw['signer_public_key']:
            error_message = "Record data is incomplete or corrupted."
            flash(error_message, "danger")
            # Redirect back to list, cannot verify
            return redirect(url_for('dashboard', view='verify_prescription'))

        # 1. Attempt Decryption
        decrypted_content = None
        try:
            encrypted_data_str = record_raw['encrypted_data'].decode('utf-8')
            decrypted_bundle_bytes = decrypt_record_aes(
                encrypted_data_str, user_attributes, record_raw['policy_str']
            )

            if not decrypted_bundle_bytes:
                error_message = "Access Denied. You do not have permission to view this prescription."
                flash(error_message, "danger")
                return redirect(url_for('dashboard', view='verify_prescription'))

            # 2. Parse and Verify Signature
            try:
                record_bundle = json.loads(decrypted_bundle_bytes)
                prescription_data_str = record_bundle['data'] # Inner JSON string
                signature_hex = record_bundle['signature']
                signer_public_key_pem_str = record_raw['signer_public_key'] # Already fetched

                is_valid_signature = verify_signature(
                    signer_public_key_pem_str.encode('utf-8'),
                    prescription_data_str.encode('utf-8'),
                    bytes.fromhex(signature_hex)
                )

                # 3. Extract LIMITED details if valid (or try even if invalid for context)
                inner_data = json.loads(prescription_data_str)
                # Fetch doctor's name separately for display
                doctor_info = conn.execute("SELECT full_name FROM doctor_profile WHERE user_id = ?", (record_raw['created_by_user_id'],)).fetchone()

                prescription_details = {
                    'patient_name': record_raw['patient_name'] or 'Unknown Patient',
                    'doctor_name': doctor_info['full_name'] if doctor_info else 'Unknown Doctor',
                    'date_issued': inner_data.get('date_issued', 'N/A'),
                    'medicines': inner_data.get('medicines', [])
                }

                # 4. Check Blockchain if dispensed (Only if signature is valid)
                if is_valid_signature:
                    dispense_log = conn.execute(
                        "SELECT 1 FROM blockchain_audit_log WHERE record_id = ? AND action = ? LIMIT 1",
                        (record_id, blockchain.ACTION_PHARMACIST_DISPENSE)
                    ).fetchone()
                    is_dispensed = bool(dispense_log)

            except (json.JSONDecodeError, KeyError, ValueError, binascii.Error, TypeError) as parse_e:
                error_message = f"Decryption OK, but content parse/verification error: {parse_e}"
                is_valid_signature = False # Cannot trust if parsing failed
            except Exception as verify_e:
                error_message = f"Signature verification failed: {verify_e}"
                is_valid_signature = False

        except UnicodeDecodeError:
             error_message = "Prescription data appears corrupted (cannot decode)."
        except Exception as decrypt_e:
             error_message = f"Decryption failed: {decrypt_e}"

        # Flash error if verification failed but show page anyway for context
        if not is_valid_signature and not error_message:
             error_message = "Signature is invalid." # Generic invalid message
        if error_message and "Access Denied" not in error_message: # Don't flash access denied again
             flash(error_message, "warning")


    except Exception as e:
        error_message = f"An unexpected error occurred: {e}"
        flash(error_message, "danger")
        print(f"--- ERROR in pharmacist_verify_details for {record_id} ---")
        traceback.print_exc()
        return redirect(url_for('dashboard', view='verify_prescription'))
    finally:
        if conn:
            conn.close()

    # --- SAFE USER DATA CONSTRUCTION for header ---
    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role'),
        'attributes': session.get('attributes', {})
    }

    # Render the NEW details template
    return render_template('pharmacist_verify_details.html',
                           user=user_data,
                           record_id=record_id,
                           prescription=prescription_details, # Contains only limited fields
                           is_valid_signature=is_valid_signature,
                           is_dispensed=is_dispensed,
                           error_message=error_message)


# --- Pharmacist Dispense Action Route (Remains mostly the same) ---

@pharmacist_bp.route('/dispense/<record_id>', methods=['POST'])
def dispense_prescription(record_id):
    """Handles the action of dispensing a prescription. Re-verifies before logging."""
    if 'user_id' not in session or session.get('role') != 'pharmacist':
         flash("Unauthorized action.", "danger")
         return redirect(url_for('login'))

    conn = None # Initialize conn
    try:
        conn = get_db_connection()
        # --- Re-verification steps (same as before) ---
        # 1. Re-fetch record and verify signature (Security Check)
        record_raw = conn.execute(
             """SELECT mr.encrypted_data, mr.policy_str, mr.created_by_user_id,
                       signer.public_key AS signer_public_key
                FROM medical_records mr
                LEFT JOIN users signer ON mr.created_by_user_id = signer.user_id
                WHERE mr.record_id = ? AND mr.record_type = 'prescription'""",
             (record_id,)
        ).fetchone()

        if not record_raw:
            flash("Prescription record not found.", "danger")
            return redirect(url_for('dashboard', view='verify_prescription'))

        if not record_raw['encrypted_data'] or not isinstance(record_raw['encrypted_data'], bytes) or not record_raw['policy_str'] or not record_raw['created_by_user_id'] or not record_raw['signer_public_key']:
             flash("Cannot dispense: Record data is incomplete or signer key is missing.", "warning")
             return redirect(url_for('pharmacist.pharmacist_verify_details', record_id=record_id)) # Back to details

        # 2. Decrypt
        user_attributes = session.get('attributes', {})
        encrypted_data_str = record_raw['encrypted_data'].decode('utf-8')
        decrypted_bundle_bytes = decrypt_record_aes(
            encrypted_data_str, user_attributes, record_raw['policy_str']
        )

        if not decrypted_bundle_bytes:
             flash("Cannot dispense: You do not have permission to decrypt this record.", "danger")
             return redirect(url_for('pharmacist.pharmacist_verify_details', record_id=record_id)) # Back to details

        # 3. Verify Signature Again
        is_valid = False
        try:
            record_bundle = json.loads(decrypted_bundle_bytes)
            prescription_data_str = record_bundle['data']
            signature_hex = record_bundle['signature']
            signer_public_key_pem_str = record_raw['signer_public_key'] # Already fetched

            is_valid = verify_signature(
                signer_public_key_pem_str.encode('utf-8'),
                prescription_data_str.encode('utf-8'),
                bytes.fromhex(signature_hex)
            )
        except Exception as verify_e:
             print(f"Dispense Error: Verification failed during dispense action: {verify_e}")
             flash("Cannot dispense: Prescription verification failed.", "danger")
             return redirect(url_for('pharmacist.pharmacist_verify_details', record_id=record_id)) # Back to details

        if not is_valid:
             flash("Cannot dispense: Prescription signature is invalid.", "danger")
             return redirect(url_for('pharmacist.pharmacist_verify_details', record_id=record_id)) # Back to details

        # 4. Check Blockchain if ALREADY dispensed (Prevent Double Dispensing)
        dispense_log = conn.execute(
            "SELECT 1 FROM blockchain_audit_log WHERE record_id = ? AND action = ? LIMIT 1",
            (record_id, blockchain.ACTION_PHARMACIST_DISPENSE)
        ).fetchone()

        if dispense_log:
            flash("This prescription has already been marked as dispensed.", "warning")
            return redirect(url_for('pharmacist.pharmacist_verify_details', record_id=record_id)) # Back to details

        # 5. Log Dispensing Action to Blockchain
        success = blockchain.log_action_to_blockchain(
            user_id=session['user_id'],
            action=blockchain.ACTION_PHARMACIST_DISPENSE,
            record_id=record_id,
            details=f"Pharmacist {session['username']} dispensed prescription {record_id}"
        )

        if success:
            flash(f"Prescription {record_id[-12:]}... successfully marked as dispensed.", "success")
        else:
            flash("Failed to log dispensing action. Please try again.", "danger")
            # Stay on details page if logging failed
            return redirect(url_for('pharmacist.pharmacist_verify_details', record_id=record_id))

    except UnicodeDecodeError:
         flash("Cannot dispense: Prescription data appears corrupted.", "danger")
         # Redirect back to details page on error during dispense
         return redirect(url_for('pharmacist.pharmacist_verify_details', record_id=record_id))
    except Exception as e:
        flash(f"An error occurred during dispensing: {e}", "danger")
        print(f"--- ERROR during dispense action for {record_id} ---")
        traceback.print_exc()
        # Redirect back to details page on error during dispense
        return redirect(url_for('pharmacist.pharmacist_verify_details', record_id=record_id))
    finally:
        if conn:
            conn.close()

    # Redirect back to the prescription list after successful dispensing
    return redirect(url_for('dashboard', view='verify_prescription'))

