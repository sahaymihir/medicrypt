import sqlite3
import os # Added for path operations
import traceback # Added for detailed error printing

# CORRECTED: Use absolute imports
from auth import register_user
from database import seed_roles, get_db_connection

# --- Directory to save dummy keys ---
DUMMY_KEYS_DIR = 'dummy_keys'

def save_private_key(username, private_key_pem):
    """Saves the private key PEM to a file."""
    if not os.path.exists(DUMMY_KEYS_DIR):
        os.makedirs(DUMMY_KEYS_DIR)
        print(f"Created directory: {DUMMY_KEYS_DIR}")

    # Sanitize username for filename (replace @, ., etc.)
    safe_filename = username.replace('@', '_at_').replace('.', '_dot_')
    filepath = os.path.join(DUMMY_KEYS_DIR, f"{safe_filename}_private_key.pem")

    try:
        with open(filepath, 'wb') as f: # Open in binary write mode
            f.write(private_key_pem)
        print(f"--- Saved private key for {username} to: {filepath}")
    except Exception as e:
        print(f"--- ERROR saving private key for {username}: {e}")


def clear_dummy_users():
    """Deletes the specific dummy users based on their generated email usernames."""
    print("Clearing old dummy users...")
    conn = get_db_connection()
    # --- UPDATED: Use the correct email-style usernames for the new names ---
    users_to_delete = (
        'mihir@admin.kmc.edu',
        'omkar@doctor.kmc.edu',
        'rishi@doctor.kmc.edu',
        'harsh@patient.kmc.edu',
        'sushmita@pharmacist.kmc.edu',
        # Keep old ones just in case they exist from previous failed runs
        'admin@admin.kmc.edu',
        'stephen@doctor.kmc.edu',
        'gregory@doctor.kmc.edu',
        'test@patient.kmc.edu',
        'walter@pharmacist.kmc.edu'
    )
    # --- END UPDATE ---

    try:
        with conn:
            # 1. Find user_ids
            user_ids_rows = conn.execute(
                f"SELECT user_id FROM users WHERE username IN ({','.join('?' for _ in users_to_delete)})",
                users_to_delete
            ).fetchall()

            if not user_ids_rows:
                print("No old dummy users found matching the specified usernames.")
                return # Exit early if no users found

            user_id_list = [row['user_id'] for row in user_ids_rows]
            print(f"Found {len(user_id_list)} users to delete with IDs: {user_id_list}")
            placeholders = ','.join('?' for _ in user_id_list)

            # 2. Delete from all dependent tables (Order matters due to FOREIGN KEYs)
            print("Deleting associated records...")
            conn.execute(f"DELETE FROM blockchain_audit_log WHERE user_id IN ({placeholders})", user_id_list)
            conn.execute(f"DELETE FROM search_index WHERE record_id IN (SELECT record_id FROM medical_records WHERE patient_user_id IN ({placeholders}) OR created_by_user_id IN ({placeholders}))", user_id_list + user_id_list) # Delete index entries first
            conn.execute(f"DELETE FROM medical_records WHERE patient_user_id IN ({placeholders}) OR created_by_user_id IN ({placeholders})", user_id_list + user_id_list)
            conn.execute(f"DELETE FROM user_attributes WHERE user_id IN ({placeholders})", user_id_list)
            conn.execute(f"DELETE FROM doctor_profile WHERE user_id IN ({placeholders})", user_id_list)
            conn.execute(f"DELETE FROM patient_profile WHERE user_id IN ({placeholders})", user_id_list)
            conn.execute(f"DELETE FROM pharmacist_profile WHERE user_id IN ({placeholders})", user_id_list)
            conn.execute(f"DELETE FROM admin_profile WHERE user_id IN ({placeholders})", user_id_list)

            # 3. Finally, delete from the main users table
            print("Deleting users...")
            conn.execute(f"DELETE FROM users WHERE user_id IN ({placeholders})", user_id_list)

            print(f"Deleted {len(user_id_list)} old dummy users and associated data.")

    except sqlite3.Error as e:
        print(f"An error occurred while clearing users: {e}.")
        print("--- Please check FOREIGN KEY constraints and table contents. ---")
        traceback.print_exc() # Print full traceback for debugging
    finally:
        conn.close()


def seed_dummy_users():
    """Creates dummy users and saves their private keys to files."""
    seed_roles() # Ensure roles exist

    print("\n--- Seeding New Dummy Users ---")

    # --- UPDATED: New user data ---
    dummy_users_data = [
        # Full Name, Password, Role, Profile Dict, Age (only for patient)
        ('Mihir Sahay', 'Admin@1234', 'admin', {'contact_email': 'mihir.admin@medcrypt.com'}, None),
        ('Omkar Nayak', 'Doctor@123', 'doctor', {'department': 'Cardiology', 'specialty': 'Interventional', 'hospital_id': 'KMC'}, None),
        ('Rishi Khandelwal', 'Doctor@456', 'doctor', {'department': 'Neurology', 'specialty': 'Epileptology', 'hospital_id': 'KMC'}, None),
        ('Harsh Singh', 'Patient@123', 'patient', {}, 28), # Patient with age 28
        ('Sushmita Sen', 'Pharm@1NET', 'pharmacist', {'pharmacy_name': 'KMC Pharmacy', 'license_number': 'PHKMC001'}, None)
    ]
    # --- END UPDATE ---

    for full_name, password, role, profile, age in dummy_users_data:
        print(f"\nRegistering {full_name} ({role})...")
        # --- MODIFIED: Capture and save the private key ---
        user_id, username, private_key = register_user(
            full_name,
            password,
            role,
            profile_data=profile, # Pass profile dict
            age=age # Pass age (will be None for non-patients)
        )
        if user_id and private_key:
            save_private_key(username, private_key)
        else:
            print(f"!!! Failed to register {full_name}. Skipping key save.")
        # --- END MODIFICATION ---

    print("\n--- New dummy user seeding complete. Check the 'dummy_keys' directory for private key files. ---")


if __name__ == "__main__":
    # Run this file directly:
    # python seed_users.py

    # 1. Clear out the specific old dummy users
    clear_dummy_users()

    # 2. Seed the new users and save their keys
    seed_dummy_users()

