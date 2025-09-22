from flask import (
    Blueprint, render_template, request, redirect, url_for, session, flash, json
)
import uuid
import json # Ensure json is imported
from datetime import date
import traceback
import pickle # For PHE deserialization
import binascii # For handling hex errors during verification
# import numpy as np # No longer needed here

# CORRECTED: Use absolute imports
from database import get_db_connection
from crypto import (
    encrypt_record_aes, sign_data, verify_signature,
    get_phe_keys, phe_encrypt, phe_decrypt,
    generate_sse_token,
    decrypt_record_aes
)
import blockchain

# Define the Blueprint
doctor_bp = Blueprint('doctor', __name__, template_folder='../../templates') # Point to main templates

# --- Helper - Load PHE keys ---
try:
    PHE_PUBLIC_KEY, PHE_PRIVATE_KEY = get_phe_keys() # Load both keys
except Exception as e:
    print(f"CRITICAL ERROR: Could not load PHE keys in doctor blueprint: {e}")
    PHE_PUBLIC_KEY = None
    PHE_PRIVATE_KEY = None # Handle gracefully

# --- Dashboard Rendering ---

def render_doctor_dashboard():
    """Fetches data and renders the appropriate doctor dashboard view."""
    if 'user_id' not in session or session.get('role') != 'doctor':
         flash("Unauthorized access.", "danger")
         return redirect(url_for('login'))

    view = request.args.get('view', 'tiles') # Default view is tiles
    patient_id_to_view = request.args.get('id', None) # For patient detail view
    search_query = request.args.get('search_query', None) # For patient search

    # --- SAFE USER DATA CONSTRUCTION ---
    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role'),
        'attributes': session.get('attributes', {})
    }
    # --- END SAFE CONSTRUCTION ---

    # --- Retrieve search/stats results from session ---
    search_results = session.pop('search_results', None)
    last_search_keyword = session.pop('last_search_keyword', None)
    last_search_type = session.pop('last_search_type', None)
    stats_results = session.pop('stats_results', None)
    # --- END Retrieve ---

    template_data = {
        'user': user_data,
        'view': view,
        'search_query': search_query,
        'patients': [],
        'patient_detail': None,
        'prescriptions': [],
        # Pass retrieved results to template
        'search_results': search_results,
        'last_search_keyword': last_search_keyword,
        'last_search_type': last_search_type,
        'stats_results': stats_results
    }

    conn = None # Initialize conn outside try
    try:
        conn = get_db_connection()

        # --- Fetch Data Based on View ---
        if view == 'patients' or view == 'patient_detail':
            patient_query = """
                SELECT pp.user_id, pp.full_name, pp.phe_age
                FROM patient_profile pp
                JOIN users u ON pp.user_id = u.user_id
                WHERE u.role_id = (SELECT role_id FROM roles WHERE role_name = 'patient')
            """
            params = []
            if search_query:
                 patient_query += " AND pp.full_name LIKE ?"
                 params.append(f"%{search_query}%")

            patient_query += " ORDER BY pp.full_name"
            patients_raw = conn.execute(patient_query, params).fetchall()

            patients_processed = []
            if patients_raw:
                 for p in patients_raw:
                     age = None
                     if p['phe_age'] and PHE_PRIVATE_KEY:
                         try:
                             decrypted_age = phe_decrypt(PHE_PRIVATE_KEY, p['phe_age'])
                             if decrypted_age is not None:
                                 age = int(decrypted_age)
                         except Exception as age_e:
                              print(f"Warning: Could not decrypt age for patient {p['user_id']}: {age_e}")
                     patients_processed.append({
                         'user_id': p['user_id'],
                         'full_name': p['full_name'],
                         'age': age
                     })
            template_data['patients'] = patients_processed

        if view == 'patient_detail' and patient_id_to_view:
             found_patient = next((p for p in template_data['patients'] if p['user_id'] == patient_id_to_view), None)
             if found_patient:
                  template_data['patient_detail'] = found_patient
                  prescriptions_raw = conn.execute(
                      """SELECT mr.record_id, mr.created_at, mr.created_by_user_id, ua.attribute_value as doctor_name
                         FROM medical_records mr
                         LEFT JOIN user_attributes ua ON mr.created_by_user_id = ua.user_id AND ua.attribute_name = 'full_name'
                         WHERE mr.patient_user_id = ? AND mr.record_type = 'prescription'
                         ORDER BY mr.created_at DESC""",
                      (patient_id_to_view,)
                  ).fetchall()
                  template_data['prescriptions'] = [dict(row) for row in prescriptions_raw] if prescriptions_raw else []
             else:
                  flash(f"Patient with ID {patient_id_to_view} not found.", "warning")
                  template_data['view'] = 'patients' # Fallback to list view

        elif view == 'prescriptions':
             prescriptions_raw = conn.execute(
                 """SELECT mr.record_id, mr.created_at, mr.patient_user_id, ua_patient.attribute_value as patient_name
                    FROM medical_records mr
                    LEFT JOIN user_attributes ua_patient ON mr.patient_user_id = ua_patient.user_id AND ua_patient.attribute_name = 'full_name'
                    WHERE mr.created_by_user_id = ? AND mr.record_type = 'prescription'
                    ORDER BY mr.created_at DESC""",
                 (session['user_id'],)
             ).fetchall()
             template_data['prescriptions'] = [dict(row) for row in prescriptions_raw] if prescriptions_raw else []

    except Exception as e:
        print(f"--- ERROR fetching data for doctor dashboard view '{view}': {e} ---")
        traceback.print_exc()
        flash(f"Error loading dashboard data: {e}", "danger")
        template_data['view'] = 'tiles' # Fallback to tiles on error
    finally:
        if conn:
            conn.close()

    return render_template('doctor_dashboard.html', **template_data)


# --- Doctor Specific Routes (Prescription, Search) ---

@doctor_bp.route('/write_prescription/<patient_id>')
def write_prescription(patient_id):
    """Shows the form for a doctor to write a new prescription."""
    if 'user_id' not in session or session.get('role') != 'doctor':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    # Fetch patient including smoking status
    patient = conn.execute(
        "SELECT user_id, full_name, smoking_status FROM patient_profile WHERE user_id = ?",
        (patient_id,)
    ).fetchone()
    medicines = conn.execute("SELECT name, strength FROM medicines ORDER BY name").fetchall()
    conn.close()

    if not patient:
        flash("Patient not found.", "danger")
        return redirect(url_for('dashboard', view='patients'))

    user_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role'),
        'attributes': session.get('attributes', {})
    }
    today_date_display = date.today().isoformat()
    return render_template('write_prescription.html',
                           user=user_data,
                           patient=patient, # Pass full patient data including smoking status
                           medicines=medicines,
                           today_date=today_date_display)


@doctor_bp.route('/create_prescription', methods=['POST'])
def create_prescription():
    """Handles the creation, signing, and encryption of a prescription."""
    if 'user_id' not in session or session.get('role') != 'doctor':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('dashboard'))

    if not PHE_PUBLIC_KEY:
         flash("PHE Public Key not loaded. Cannot encrypt numeric data.", "warning")

    patient_id = request.form.get('patient_id') # Get patient_id early for redirect target

    # --- Read private key from file upload ---
    private_key_file = request.files.get('signing_private_key_file')
    private_key_pem_bytes = None

    if not private_key_file or private_key_file.filename == '':
        flash("Signing private key file is required.", "danger")
        return redirect(url_for('doctor.write_prescription', patient_id=patient_id)) if patient_id else redirect(url_for('dashboard'))

    try:
        private_key_pem_bytes = private_key_file.read()
        if b'-----BEGIN RSA PRIVATE KEY-----' not in private_key_pem_bytes:
             flash('Invalid private key file format (missing PEM header).', 'danger')
             return redirect(url_for('doctor.write_prescription', patient_id=patient_id)) if patient_id else redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error reading signing private key file: {e}', 'danger')
        return redirect(url_for('doctor.write_prescription', patient_id=patient_id)) if patient_id else redirect(url_for('dashboard'))
    # --- END Key Reading ---


    conn = None # Initialize connection
    try:
        # Get data from form
        heart_rate_str = request.form.get('heart_rate')
        # Get BP components
        systolic_bp_str = request.form.get('systolic_bp')
        diastolic_bp_str = request.form.get('diastolic_bp')
        weight_str = request.form.get('weight') # Assuming weight is still 'weight' in form
        height_str = request.form.get('height') # Assuming height is still 'height' in form
        diagnosis_str = request.form.get('diagnosis')
        cause_str = request.form.get('cause') # Get cause
        date_issued_str = date.today().isoformat()

        # Validate BP
        systolic_bp = int(systolic_bp_str) if systolic_bp_str and systolic_bp_str.isdigit() else None
        diastolic_bp = int(diastolic_bp_str) if diastolic_bp_str and diastolic_bp_str.isdigit() else None

        medicine_names = request.form.getlist('medicine_name')
        frequencies = request.form.getlist('frequency')
        remarks_list = request.form.getlist('remarks')

        medicines_data = []
        for name, freq, remark in zip(medicine_names, frequencies, remarks_list):
            if name and freq:
                medicines_data.append({"medicine": name, "frequency": freq, "remarks": remark or ""})

        prescription_data = {
            'patient_id': patient_id,
            'doctor_id': session['user_id'],
            'doctor_name': session.get('attributes', {}).get('full_name', session.get('username')),
            'date_issued': date_issued_str,
            'height_cm': height_str,
            'weight_kg': weight_str,
            'systolic_bp': systolic_bp, # Store integer
            'diastolic_bp': diastolic_bp, # Store integer
            'heart_rate': heart_rate_str,
            'diagnosis': diagnosis_str,
            'cause': cause_str, # Store cause
            'medicines': medicines_data,
            'notes': request.form.get('notes')
        }
        prescription_json_str = json.dumps(prescription_data, sort_keys=True)

        signature = sign_data(private_key_pem_bytes, prescription_json_str.encode('utf-8'))
        if not signature:
            raise ValueError("Failed to sign prescription data. Key might be invalid.")

        full_record_to_encrypt = {
            'data': prescription_json_str,
            'signature': signature.hex()
        }
        full_record_json = json.dumps(full_record_to_encrypt)

        # --- MODIFIED POLICY (Simpler for Testing) ---
        policy = f"role:doctor OR role:pharmacist OR role:admin OR user_id:{patient_id}"
        # --- END MODIFICATION ---

        encrypted_data_bytes, policy_str_used = encrypt_record_aes(
            full_record_json.encode('utf-8'), policy
        )
        if not encrypted_data_bytes:
             raise ValueError("A server error occurred during prescription encryption.")

        # PHE Encrypt numeric fields if possible
        phe_hr_encrypted = None
        if PHE_PUBLIC_KEY and heart_rate_str and heart_rate_str.isdigit():
            try: phe_hr_encrypted = phe_encrypt(PHE_PUBLIC_KEY, int(heart_rate_str))
            except Exception as e: print(f"Warning: Failed to PHE encrypt HR: {e}")

        phe_sys_encrypted = None
        if PHE_PUBLIC_KEY and systolic_bp is not None:
            try: phe_sys_encrypted = phe_encrypt(PHE_PUBLIC_KEY, systolic_bp)
            except Exception as e: print(f"Warning: Failed to PHE encrypt Systolic BP: {e}")

        phe_dia_encrypted = None
        if PHE_PUBLIC_KEY and diastolic_bp is not None:
            try: phe_dia_encrypted = phe_encrypt(PHE_PUBLIC_KEY, diastolic_bp)
            except Exception as e: print(f"Warning: Failed to PHE encrypt Diastolic BP: {e}")

        # Store in DB
        record_id = str(uuid.uuid4())
        conn = get_db_connection()
        with conn:
            # --- Fetch patient's smoking status ---
            smoking_status_row = conn.execute(
                "SELECT smoking_status FROM patient_profile WHERE user_id = ?",
                (patient_id,)
            ).fetchone()
            smoking_status = smoking_status_row['smoking_status'] if smoking_status_row else 'unknown'
            # --- End fetch ---

            # --- UPDATED INSERT with BP columns ---
            conn.execute(
                """INSERT INTO medical_records (record_id, patient_user_id, record_type, encrypted_data, policy_str,
                                             created_by_user_id, phe_heart_rate, phe_systolic, phe_diastolic)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", # 9 placeholders
                (record_id, patient_id, 'prescription',
                 encrypted_data_bytes,
                 policy_str_used,
                 session['user_id'],
                 phe_hr_encrypted, phe_sys_encrypted, phe_dia_encrypted) # 9 values
            )
            # --- END UPDATE ---

            # Add tokens to search index and profile index
            if diagnosis_str:
                diag_token = generate_sse_token(diagnosis_str)
                conn.execute("INSERT INTO search_index (keyword_token, record_id) VALUES (?, ?)", (diag_token, record_id))
                print(f"Indexed diagnosis token '{diagnosis_str}' for record {record_id}")
            if cause_str: # Index cause
                cause_token = generate_sse_token(cause_str)
                conn.execute("INSERT INTO search_index (keyword_token, record_id) VALUES (?, ?)", (cause_token, record_id))
                print(f"Indexed cause token '{cause_str}' for record {record_id}")

            # --- Index smoking status in patient_profile_index ---
            smoke_token = generate_sse_token(smoking_status)
            conn.execute(
                "INSERT OR IGNORE INTO patient_profile_index (user_id, keyword_token) VALUES (?, ?)",
                (patient_id, smoke_token)
            )
            print(f"Ensured smoking status token '{smoking_status}' indexed for patient {patient_id}")
            # --- End Index ---

        # Log action to blockchain outside the 'with conn:' block
        blockchain.log_action_to_blockchain(
            user_id=session['user_id'],
            action=blockchain.ACTION_CREATE_PRESCRIPTION,
            record_id=record_id,
            details=f"Doctor created prescription for patient {patient_id}"
        )

        flash("Prescription created, signed, encrypted successfully!", "success")
        return redirect(url_for('dashboard', view='patient_detail', id=patient_id))

    except (ValueError, TypeError) as val_e: # Catch specific validation errors
        flash(f"Invalid input: {val_e}", "danger")
        traceback.print_exc()
        # Redirect back to form
        return redirect(url_for('doctor.write_prescription', patient_id=patient_id)) if patient_id else redirect(url_for('dashboard', view='patients'))
    except Exception as e:
        flash(f"Error creating prescription: {e}", "danger")
        traceback.print_exc()
        # Redirect back to form
        return redirect(url_for('doctor.write_prescription', patient_id=patient_id)) if patient_id else redirect(url_for('dashboard', view='patients'))
    finally:
        if conn:
            conn.close()


# --- Route to View/Verify/Decrypt a Single Prescription ---
@doctor_bp.route('/view_prescription/<record_id>')
def view_prescription(record_id):
    """Verifies and decrypts a specific prescription record (accessible by Doctor or Patient)."""
    if 'user_id' not in session: # Check if logged in
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    logged_in_user_id = session['user_id']
    logged_in_role = session.get('role')
    # --- IMPORTANT FIX: Create attributes dict including role ---
    # Start with attributes from session, ensuring it's a copy
    user_attributes = session.get('attributes', {}).copy()
    # Add the logged-in user's ID and role, which are crucial for policy checks
    user_attributes['user_id'] = logged_in_user_id
    user_attributes['role'] = logged_in_role
    # --- END FIX ---

    conn = get_db_connection()
    record_data = None
    verification_status = "Not Checked"
    decryption_status = "Not Attempted"
    prescription_content = None
    error_message = None
    patient_info = None
    prescribing_doctor_info = None
    is_valid_signature = False

    try:
        record_raw = conn.execute(
            """SELECT mr.*, signer.public_key AS signer_public_key
               FROM medical_records mr
               LEFT JOIN users signer ON mr.created_by_user_id = signer.user_id
               WHERE mr.record_id = ? AND mr.record_type = 'prescription'""",
            (record_id,)
        ).fetchone()

        if not record_raw:
            flash("Prescription record not found.", "danger")
            return redirect(url_for('dashboard')) # Redirect to appropriate dashboard

        record_data = dict(record_raw)
        patient_user_id = record_data.get('patient_user_id')
        created_by_user_id = record_data.get('created_by_user_id')

        # --- AUTHORIZATION Check (Simplified - relies more on policy now) ---
        # Basic check to ensure the user isn't completely unrelated,
        # but the main check happens during decryption via the policy.
        is_potentially_authorized = False
        if logged_in_role == 'patient' and logged_in_user_id == patient_user_id:
            is_potentially_authorized = True
        elif logged_in_role == 'doctor': # Doctors are potentially authorized
             is_potentially_authorized = True
        elif logged_in_role in ['pharmacist', 'admin']: # Other roles potentially authorized
             is_potentially_authorized = True

        if not is_potentially_authorized:
            flash("You do not have permission to view this specific record type.", "danger")
            return redirect(url_for('dashboard'))
        # --- End Authorization Check ---


        # Fetch patient and doctor profile info
        if patient_user_id:
             patient_info_raw = conn.execute("SELECT user_id, full_name, phe_age FROM patient_profile WHERE user_id = ?", (patient_user_id,)).fetchone()
             if patient_info_raw: patient_info = dict(patient_info_raw)
        if created_by_user_id:
             doctor_info_raw = conn.execute("SELECT user_id, full_name, department, specialty, hospital_id FROM doctor_profile WHERE user_id = ?", (created_by_user_id,)).fetchone()
             if doctor_info_raw: prescribing_doctor_info = dict(doctor_info_raw)


        encrypted_data_input = record_data.get('encrypted_data')
        policy_str = record_data.get('policy_str')
        signer_public_key_pem = record_data.get('signer_public_key')

        # Attempt Decryption
        if encrypted_data_input and policy_str:
            encrypted_data_str = None
            if isinstance(encrypted_data_input, bytes):
                try: encrypted_data_str = encrypted_data_input.decode('utf-8')
                except UnicodeDecodeError: error_message = "Corrupted encrypted data in database (not valid UTF-8)."
            else: error_message = f"Unexpected encrypted data type in DB: {type(encrypted_data_input)}. Expected bytes."

            if encrypted_data_str:
                # --- Pass the correctly populated user_attributes ---
                decrypted_bundle_bytes = decrypt_record_aes(encrypted_data_str, user_attributes, policy_str)
                # --- END ---

                if decrypted_bundle_bytes:
                    decryption_status = "Success"
                    try:
                        # Attempt to decode as UTF-8 first
                        try:
                            decrypted_bundle_str = decrypted_bundle_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                             # Handle potential non-UTF8 data from placeholder seeding
                             if decrypted_bundle_bytes.startswith(b"SEED:"):
                                 print(f"Record {record_id} contains placeholder seed data.")
                                 decrypted_bundle_str = decrypted_bundle_bytes[5:].decode('utf-8') # Remove "SEED:" prefix
                                 # Seeded data isn't signed, skip verification
                                 prescription_content = json.loads(decrypted_bundle_str)
                                 verification_status = "Not Applicable (Seeded Data)"
                                 is_valid_signature = False # Cannot be valid
                                 # Skip further verification logic for seeded data
                                 raise StopIteration("Seeded data, skip verification")
                             else:
                                 raise # Re-raise if not seed data

                        record_bundle = json.loads(decrypted_bundle_str)
                        prescription_data_str = record_bundle.get('data')
                        signature_hex = record_bundle.get('signature')

                        if prescription_data_str and signature_hex and signer_public_key_pem:
                             is_valid = verify_signature(
                                 signer_public_key_pem.encode('utf-8'),
                                 prescription_data_str.encode('utf-8'),
                                 bytes.fromhex(signature_hex)
                             )
                             verification_status = "Valid" if is_valid else "INVALID / TAMPERED"
                             is_valid_signature = is_valid
                             prescription_content = json.loads(prescription_data_str)

                             # Decrypt Patient Age from Profile (if available)
                             if patient_info and patient_info.get('phe_age') and PHE_PRIVATE_KEY:
                                 try:
                                     decrypted_age = phe_decrypt(PHE_PRIVATE_KEY, patient_info['phe_age'])
                                     if decrypted_age is not None:
                                         prescription_content['age'] = int(decrypted_age)
                                 except Exception as age_e:
                                      print(f"Warning: Could not decrypt age for patient {patient_user_id} in view_prescription: {age_e}")

                        elif not signer_public_key_pem:
                             verification_status = "Cannot Verify (Signer key missing)"
                             is_valid_signature = False
                             try:
                                 prescription_content = json.loads(prescription_data_str)
                             except Exception: # Catch potential JSON errors here too
                                 pass # Keep content None if inner JSON is also bad
                        else:
                             verification_status = "Error (Missing data/signature in bundle)"
                             is_valid_signature = False
                             error_message = "Decrypted bundle is incomplete."
                             try: prescription_content = json.loads(prescription_data_str)
                             except Exception: pass

                    except StopIteration: # Catch the StopIteration for seeded data
                        pass # Status already set above
                    except (json.JSONDecodeError, ValueError, KeyError, binascii.Error) as e:
                         decryption_status = "Success (Content Parse/Verify Error)"
                         verification_status = "Cannot Verify (Parse Error)"
                         is_valid_signature = False
                         error_message = f"Could not parse/verify decrypted content: {e}"
                         try: prescription_content = {'raw_data': prescription_data_str if 'prescription_data_str' in locals() else decrypted_bundle_bytes.decode('utf-8','ignore')}
                         except Exception: prescription_content = {'raw_data': '[Binary or Unparseable Content]'}
                    except Exception as e:
                         decryption_status = "Success (Verification Error)"
                         verification_status = f"Error during verification: {e}"
                         is_valid_signature = False
                         error_message = str(e)
                         try: prescription_content = json.loads(prescription_data_str)
                         except Exception: pass # Keep content None if inner JSON is bad
                else:
                     decryption_status = "ACCESS DENIED"
                     verification_status = "Cannot Verify (Access Denied)"
                     is_valid_signature = False
                     error_message = "Permission denied based on policy."

            # else: error_message already set during initial decode/type check
        elif not encrypted_data_input: error_message = "Encrypted data is missing."; decryption_status = verification_status = "Error"; is_valid_signature = False
        elif not policy_str: error_message = "Policy string is missing."; decryption_status = verification_status = "Error"; is_valid_signature = False

    except Exception as e:
        flash(f"An error occurred while fetching the prescription: {e}", "danger")
        error_message = str(e)
        decryption_status = verification_status = "Failed to Load"; is_valid_signature = False
        traceback.print_exc()
    finally:
        if conn: conn.close()

    user_header_data = {
        'display_name': session.get('attributes', {}).get('full_name', session.get('username')),
        'username': session.get('username'),
        'role': session.get('role'),
        'attributes': session.get('attributes', {})
    }

    if not patient_info: patient_info = {'user_id': patient_user_id or 'Unknown', 'full_name': 'Unknown Patient'}
    if not prescribing_doctor_info: prescribing_doctor_info = {'user_id': created_by_user_id or 'Unknown', 'full_name': 'Unknown Doctor'}

    return render_template('prescription_view.html',
                           user=user_header_data,
                           record_id=record_id,
                           patient=patient_info,
                           prescribing_doctor=prescribing_doctor_info,
                           prescription=prescription_content,
                           is_valid_signature=is_valid_signature,
                           verification_status_detail=verification_status,
                           decryption_status_detail=decryption_status,
                           error_message=error_message)


@doctor_bp.route('/keyword_search', methods=['POST'])
def doctor_keyword_search():
    """Handles encrypted keyword search for diagnosis or cause."""
    if 'user_id' not in session or session.get('role') != 'doctor':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    search_keyword = request.form.get('search_keyword')
    search_type = request.form.get('search_type', 'diagnosis') # 'diagnosis' or 'cause'

    results = []
    conn = None # Initialize conn
    if search_keyword:
        search_token = generate_sse_token(search_keyword)
        print(f"Doctor {session['user_id']} searching for {search_type} token: {search_token} (keyword: '{search_keyword}')") # Log search

        conn = get_db_connection()
        try:
            # Join search index with medical records and patient profile
            query = """
                SELECT si.record_id, mr.created_at, pp.full_name as patient_name
                FROM search_index si
                JOIN medical_records mr ON si.record_id = mr.record_id
                JOIN patient_profile pp ON mr.patient_user_id = pp.user_id
                WHERE si.keyword_token = ?
                ORDER BY mr.created_at DESC
                LIMIT 50
            """
            results_raw = conn.execute(query, (search_token,)).fetchall()
            results = [dict(row) for row in results_raw]
            print(f"Found {len(results)} records matching token.")

            # Log search to blockchain
            blockchain.log_action_to_blockchain(
                user_id=session['user_id'],
                action=blockchain.ACTION_DOCTOR_KEYWORD_SEARCH,
                details=f"Searched for {search_type}: '{search_keyword}'. Found {len(results)} records."
            )

        except Exception as e:
            flash(f"Error during search: {e}", "danger")
            print(f"Error executing keyword search: {e}")
            traceback.print_exc()
        finally:
            if conn: conn.close()

    # Store results in session for display on redirect
    session['search_results'] = results
    session['last_search_keyword'] = search_keyword
    session['last_search_type'] = search_type
    session.modified = True

    return redirect(url_for('dashboard', view='insights'))
