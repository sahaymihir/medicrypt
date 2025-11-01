import os
import random
import uuid
import json
from datetime import date, timedelta
import traceback

# --- Project Imports ---
# Ensure these imports work relative to where you run the script
# If running from the root 'gemini' folder, they should be fine.
try:
    from auth import register_user
    from crypto import (
        encrypt_record_aes, sign_data, get_phe_keys, phe_encrypt, generate_sse_token
    )
    from database import get_db_connection
    import blockchain
except ImportError as e:
    print(f"Error importing project modules: {e}")
    print("Please ensure you are running this script from the correct directory (e.g., the root 'gemini' folder)")
    exit(1)

# --- Configuration ---
NUM_DOCTORS = 15
NUM_PATIENTS = 50
NUM_PRESCRIPTIONS_PER_PATIENT = random.randint(2, 4) # Each patient gets 2-4 prescriptions
KEYS_DIRECTORY = "dummy_keys_large"
DEFAULT_PASSWORD = "Password123!" # Use a strong default password

# --- Sample Data ---
DOCTOR_NAMES = [
    "Aditi Sharma", "Vikram Singh", "Priya Patel", "Rohan Mehta", "Neha Gupta",
    "Arjun Desai", "Ananya Reddy", "Kabir Joshi", "Mira Krishnan", "Dev Nair",
    "Saanvi Rao", "Ishaan Kumar", "Diya Verma", "Aarav Choudhury", "Pari Saxena"
]
PATIENT_NAMES = [
    "Aadhya Iyer", "Aarush Malhotra", "Advika Bannerjee", "Agastya Chatterjee", "Alia Dutta",
    "Anika Ghosh", "Anvi Majumdar", "Atharv Basu", "Avani Sen", "Ayaan Das",
    "Charvi Bhattacharya", "Dhruv Mazumdar", "Eesha Chakraborty", "Gautam Sarkar", "Inaaya Guha",
    "Ishana Thakur", "Jiya Roy", "Kabir Dasgupta", "Kavya Nandi", "Krish Bose",
    "Lavanya Sengupta", "Manan Haldar", "Myra Dhar", "Neel Kar", "Nitara Pal",
    "Ojas Choudhury", "Prisha Seal", "Reyansh Mahato", "Rhea Mitra", "Rudra Paul",
    "Sai Barman", "Samaira Adhikari", "Shaurya Debnath", "Siya Mondal", "Soham Saha",
    "Tara Kundu", "Utkarsh Biswas", "Vanya Nath", "Vihaan Maity", "Yashvi Ghosh",
    "Zara Nag", "Zoya Biswas", "Advait Sharma", "Anvi Singh", "Arnav Gupta",
    "Ishani Patel", "Neil Kumar", "Riya Mehta", "Veer Desai", "Aarohi Reddy"
]

DEPARTMENTS = ["Cardiology", "Neurology", "Oncology", "Pediatrics", "Orthopedics", "General Medicine", "Dermatology"]
SPECIALTIES = ["Heart Specialist", "Brain Surgeon", "Cancer Specialist", "Child Specialist", "Bone Doctor", "GP", "Skin Doctor"]
HOSPITALS = ["KMC", "Manipal Hospital", "Kasturba Annex"]

SMOKING_STATUSES = ['smoker', 'non-smoker', 'former', 'unknown']

DIAGNOSES = ["Hypertension", "Type 2 Diabetes", "Asthma", "Migraine", "Arthritis", "Heart Disease", "Flu", "Pneumonia", "COVID-19"]
CAUSES = ["Genetic", "Lifestyle", "Infection", "Environmental", "Age-related", "Unknown", "Viral", "Bacterial"]

MEDICINES = [ # List of (Name, Strength) tuples
    ("Paracetamol", "500mg"), ("Ibuprofen", "400mg"), ("Amoxicillin", "250mg"),
    ("Metformin", "500mg"), ("Amlodipine", "5mg"), ("Atorvastatin", "10mg"),
    ("Salbutamol Inhaler", "100mcg"), ("Lisinopril", "10mg"), ("Omeprazole", "20mg")
]
FREQUENCIES = ["1-0-1", "0-1-0", "1-1-1", "As needed", "Once daily", "Twice daily"]

# --- Helper Functions ---

def create_user_and_key(full_name, role_name, profile_data=None, age=None, smoking_status='unknown'):
    """Registers user, saves private key, returns user_id and key path."""
    print(f"Registering {role_name}: {full_name}...")
    user_id, username, private_key_pem = register_user(
        full_name, DEFAULT_PASSWORD, role_name, profile_data, age, smoking_status
    )
    if user_id and private_key_pem:
        key_filename = f"{username.replace('@', '_at_').replace('.', '_dot_')}_private_key.pem"
        key_path = os.path.join(KEYS_DIRECTORY, key_filename)
        try:
            with open(key_path, 'wb') as f:
                f.write(private_key_pem)
            print(f"   Saved private key to: {key_path}")
            return user_id, username, key_path
        except IOError as e:
            print(f"   ERROR saving private key for {username}: {e}")
            return None, None, None
    else:
        print(f"   ERROR registering user {full_name}.")
        return None, None, None

def create_prescription_record(doctor_id, patient_id, doctor_key_pem_bytes):
    """Creates a realistic, encrypted prescription record."""
    conn = get_db_connection()
    try:
        # Fetch doctor and patient names
        doc_name_row = conn.execute("SELECT attribute_value FROM user_attributes WHERE user_id = ? AND attribute_name = 'full_name'", (doctor_id,)).fetchone()
        patient_name_row = conn.execute("SELECT full_name, smoking_status FROM patient_profile WHERE user_id = ?", (patient_id,)).fetchone() # Fetch smoking status too

        if not doc_name_row or not patient_name_row:
            print(f"   Skipping prescription: Cannot find doctor/patient profile info.")
            return

        doctor_name = doc_name_row['attribute_value']
        patient_name = patient_name_row['full_name']
        patient_smoking_status = patient_name_row['smoking_status'] # Needed for indexing later

        print(f"   Creating prescription: Dr. {doctor_name} -> {patient_name}")

        # Generate realistic-ish vitals
        heart_rate = random.randint(60, 100)
        systolic_bp = random.randint(110, 160)
        diastolic_bp = random.randint(70, 100)
        weight = random.randint(50, 100)
        height = random.randint(150, 190)
        diagnosis = random.choice(DIAGNOSES)
        cause = random.choice(CAUSES)
        date_issued_str = (date.today() - timedelta(days=random.randint(0, 365))).isoformat()

        # Select medicines
        num_meds = random.randint(1, 3)
        medicines_prescribed = random.sample(MEDICINES, num_meds)
        medicines_data = []
        for med_name, strength in medicines_prescribed:
            medicines_data.append({
                "medicine": f"{med_name} {strength}",
                "frequency": random.choice(FREQUENCIES),
                "remarks": random.choice(["Take after food", "Take before sleep", "", "Monitor side effects"])
            })

        prescription_data = {
            'patient_id': patient_id,
            'doctor_id': doctor_id,
            'doctor_name': doctor_name,
            'date_issued': date_issued_str,
            'height_cm': str(height),
            'weight_kg': str(weight),
            'systolic_bp': systolic_bp,
            'diastolic_bp': diastolic_bp,
            'heart_rate': str(heart_rate),
            'diagnosis': diagnosis,
            'cause': cause,
            'medicines': medicines_data,
            'notes': random.choice(["Follow up in 2 weeks.", "Monitor BP daily.", "", "Rest well."])
        }
        prescription_json_str = json.dumps(prescription_data, sort_keys=True)

        # Sign the data
        signature = sign_data(doctor_key_pem_bytes, prescription_json_str.encode('utf-8'))
        if not signature:
            raise ValueError(f"Failed to sign prescription for patient {patient_id}")

        full_record_to_encrypt = {
            'data': prescription_json_str,
            'signature': signature.hex()
        }
        full_record_json = json.dumps(full_record_to_encrypt)

        # Encrypt using AES with policy
        policy = f"role:doctor OR role:pharmacist OR role:admin OR user_id:{patient_id}"
        encrypted_data_bytes, policy_str_used = encrypt_record_aes(
            full_record_json.encode('utf-8'), policy
        )
        if not encrypted_data_bytes:
             raise ValueError(f"Encryption failed for patient {patient_id}")

        # PHE Encrypt numeric fields
        pub_key, _ = get_phe_keys()
        phe_hr_encrypted = phe_encrypt(pub_key, heart_rate) if pub_key else None
        phe_sys_encrypted = phe_encrypt(pub_key, systolic_bp) if pub_key else None
        phe_dia_encrypted = phe_encrypt(pub_key, diastolic_bp) if pub_key else None

        # Store in DB
        record_id = str(uuid.uuid4())
        with conn:
            conn.execute(
                """INSERT INTO medical_records (record_id, patient_user_id, record_type, encrypted_data, policy_str,
                                             created_by_user_id, phe_heart_rate, phe_systolic, phe_diastolic, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (record_id, patient_id, 'prescription',
                 encrypted_data_bytes, # Storing bytes directly (or encoded string if needed)
                 policy_str_used,
                 doctor_id,
                 phe_hr_encrypted, phe_sys_encrypted, phe_dia_encrypted,
                 date_issued_str + "T12:00:00") # Add a dummy time to the date
            )

            # Add SSE tokens
            diag_token = generate_sse_token(diagnosis)
            conn.execute("INSERT INTO search_index (keyword_token, record_id) VALUES (?, ?)", (diag_token, record_id))
            cause_token = generate_sse_token(cause)
            conn.execute("INSERT INTO search_index (keyword_token, record_id) VALUES (?, ?)", (cause_token, record_id))
            # Smoking status token is already added during patient registration

        # Log to blockchain
        blockchain.log_action_to_blockchain(
            user_id=doctor_id,
            action=blockchain.ACTION_CREATE_PRESCRIPTION,
            record_id=record_id,
            details=f"Doctor created prescription for patient {patient_id} (Seeded)"
        )
        print(f"      -> Prescription {record_id[:8]}... created.")

    except Exception as e:
        print(f"   ERROR creating prescription record: {e}")
        traceback.print_exc()
    finally:
        if conn:
            conn.close()

# --- Main Seeding Logic ---

if __name__ == "__main__":
    print("--- Starting Large Data Seeding ---")

    # Ensure keys directory exists
    if not os.path.exists(KEYS_DIRECTORY):
        os.makedirs(KEYS_DIRECTORY)
        print(f"Created directory: {KEYS_DIRECTORY}")

    doctors = [] # List to store (user_id, username, key_path)
    patients = [] # List to store user_ids

    # Create Doctors
    print(f"\n--- Creating {NUM_DOCTORS} Doctors ---")
    doc_names_to_use = random.sample(DOCTOR_NAMES, min(NUM_DOCTORS, len(DOCTOR_NAMES)))
    for i, name in enumerate(doc_names_to_use):
        dept = random.choice(DEPARTMENTS)
        spec = random.choice(SPECIALTIES) # Assign random specialty
        hosp = random.choice(HOSPITALS)
        profile_data = {'department': dept, 'specialty': spec, 'hospital_id': hosp}
        result = create_user_and_key(name, 'doctor', profile_data)
        if result[0]: # Check if user_id is not None
            doctors.append(result)
        if len(doctors) >= NUM_DOCTORS:
            break # Stop if we reach the desired number

    # Create Patients
    print(f"\n--- Creating {NUM_PATIENTS} Patients ---")
    patient_names_to_use = random.sample(PATIENT_NAMES, min(NUM_PATIENTS, len(PATIENT_NAMES)))
    for i, name in enumerate(patient_names_to_use):
        age = random.randint(18, 80)
        status = random.choice(SMOKING_STATUSES)
        result = create_user_and_key(name, 'patient', age=age, smoking_status=status)
        if result[0]: # Check if user_id is not None
            patients.append(result[0]) # Only need the user_id
        if len(patients) >= NUM_PATIENTS:
            break

    # Create Prescriptions
    print(f"\n--- Creating Prescriptions ---")
    if not doctors or not patients:
        print("Cannot create prescriptions: No doctors or patients were created successfully.")
    else:
        num_created = 0
        target_prescriptions = NUM_PATIENTS * NUM_PRESCRIPTIONS_PER_PATIENT
        # Try to ensure each patient gets prescriptions, cycle through doctors
        for i, patient_id in enumerate(patients):
            for j in range(NUM_PRESCRIPTIONS_PER_PATIENT):
                doctor_id, _, doctor_key_path = doctors[ (i + j) % len(doctors) ] # Cycle through doctors

                # Load doctor's private key
                try:
                    with open(doctor_key_path, 'rb') as f:
                        doctor_key_pem_bytes = f.read()
                except Exception as e:
                    print(f"   Skipping prescription: Could not load key {doctor_key_path} for Dr. {doctors[(i+j)%len(doctors)][1]}. Error: {e}")
                    continue

                create_prescription_record(doctor_id, patient_id, doctor_key_pem_bytes)
                num_created += 1

        print(f"\n--- Finished creating {num_created} prescriptions. ---")


    print("\n--- Seeding Complete ---")
