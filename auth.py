import sqlite3
import uuid
import bcrypt
import re
import os
import traceback # Ensure traceback is imported

# CORRECTED: Use absolute imports
from database import get_db_connection
# generate_sse_token added to imports
from crypto import generate_rsa_keys, get_phe_keys, phe_encrypt, generate_sse_token
from Crypto.PublicKey import RSA # Import RSA for key verification

# --- Security Functions ---

def hash_password(password):
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed_password):
    """Checks if a password matches its hash."""
    try:
        # Ensure hashed_password is bytes
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except (ValueError, TypeError) as e:
        print(f"Error checking password hash: {e}")
        return False

def is_password_strong(password):
    """Checks if a password meets strength requirements."""
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password): return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password): return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): return False, "Password must contain at least one special character."
    return True, ""


# --- User Management Functions ---

def _generate_unique_username(conn, full_name, role_name):
    """Generates a unique email-style username."""
    base_name = full_name.split()[0].lower() if full_name else 'user'
    domain = f"{role_name}.kmc.edu" # Example domain
    username = f"{base_name}@{domain}"
    counter = 1
    while True:
        cursor = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is None:
            return username
        counter += 1
        username = f"{base_name}{counter}@{domain}"

# Added smoking_status parameter
def register_user(full_name, password, role_name, profile_data=None, age=None, smoking_status='unknown'):
    """
    Registers a new user, hashes password, generates keys (returns private key),
    creates profile, PHE-encrypts age for patients, adds SSE tokens.

    Returns:
        (str, str, bytes): Tuple of (user_id, username, private_key_pem) or (None, None, None) on failure.
    """
    if not profile_data: profile_data = {}

    print(f"Attempting to register '{full_name}' as '{role_name}'...")
    password_hash = hash_password(password)
    user_id = str(uuid.uuid4())

    conn = get_db_connection()
    try:
        with conn:
            # 1. Generate unique username
            username = _generate_unique_username(conn, full_name, role_name)
            print(f"Generated username: {username}")

            # 2. Get role_id
            role = conn.execute("SELECT role_id FROM roles WHERE role_name = ?", (role_name,)).fetchone()
            if not role:
                print(f"Error: Role '{role_name}' not found.")
                return None, None, None

            # 3. Generate RSA keys
            private_key_pem, public_key_pem = generate_rsa_keys()

            # 4. Insert into 'users' table (without private key)
            conn.execute(
                """INSERT INTO users (user_id, username, password_hash, role_id, public_key)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, username, password_hash, role['role_id'], public_key_pem.decode('utf-8'))
            )

            # 5. Store Profile Data and Attributes
            user_attributes_dict = {'full_name': full_name, 'role': role_name}
            phe_age_encrypted = None

            if role_name == 'patient':
                if age is not None:
                    try:
                        pub_key, _ = get_phe_keys()
                        if pub_key:
                            phe_age_encrypted = phe_encrypt(pub_key, int(age))
                            print(f"PHE-encrypted age for patient {user_id}")
                        else:
                            print("WARNING: Could not load PHE public key. Age will not be encrypted.")
                    except Exception as e:
                        print(f"WARNING: Failed to PHE encrypt age {age}: {e}")

                # Ensure smoking_status is valid, default to 'unknown'
                valid_statuses = ['smoker', 'non-smoker', 'former', 'unknown']
                if smoking_status not in valid_statuses:
                    smoking_status = 'unknown'

                conn.execute(
                    "INSERT INTO patient_profile (user_id, full_name, phe_age, smoking_status) VALUES (?, ?, ?, ?)",
                    (user_id, full_name, phe_age_encrypted, smoking_status) # Add smoking_status
                )
                user_attributes_dict['user_id'] = user_id
                user_attributes_dict['smoking_status'] = smoking_status # Add to attributes for policy checks if needed

                # --- ADD SSE Token for Smoking Status ---
                try:
                    smoking_token = generate_sse_token(smoking_status)
                    conn.execute(
                        "INSERT INTO patient_profile_index (keyword_token, user_id) VALUES (?, ?)",
                        (smoking_token, user_id)
                    )
                    print(f"Indexed smoking status '{smoking_status}' for patient {user_id}")
                except Exception as sse_e:
                    print(f"WARNING: Failed to create/insert SSE token for smoking status: {sse_e}")
                # --- END ADD SSE ---


            elif role_name == 'doctor':
                dept = profile_data.get('department')
                hosp = profile_data.get('hospital_id', 'KMC_Main') # Default hospital
                conn.execute(
                    "INSERT INTO doctor_profile (user_id, full_name, department, specialty, hospital_id) VALUES (?, ?, ?, ?, ?)",
                    (user_id, full_name, dept, profile_data.get('specialty'), hosp)
                )
                if dept: user_attributes_dict['department'] = dept
                if hosp: user_attributes_dict['hospital'] = hosp

            elif role_name == 'admin':
                conn.execute("INSERT INTO admin_profile (user_id, full_name, contact_email) VALUES (?, ?, ?)",
                             (user_id, full_name, profile_data.get('contact_email')))

            elif role_name == 'pharmacist':
                conn.execute("INSERT INTO pharmacist_profile (user_id, full_name, pharmacy_name, license_number) VALUES (?, ?, ?, ?)",
                             (user_id, full_name, profile_data.get('pharmacy_name'), profile_data.get('license_number')))
                if profile_data.get('pharmacy_name'):
                     user_attributes_dict['pharmacy'] = profile_data['pharmacy_name']


            # 6. Add all collected attributes to user_attributes table
            for attr_name, attr_val in user_attributes_dict.items():
                 if attr_val is not None:
                     try:
                         conn.execute("INSERT INTO user_attributes (user_id, attribute_name, attribute_value) VALUES (?, ?, ?)",
                                      (user_id, attr_name, str(attr_val))) # Ensure value is string
                     except sqlite3.IntegrityError:
                         # Handle potential duplicates if attributes somehow overlap (e.g., full_name)
                         print(f"Attribute '{attr_name}' likely already exists for user {user_id}, skipping duplicate insert.")


        print(f"Successfully registered user '{username}' (ID: {user_id}).")
        # --- RETURN PRIVATE KEY ---
        return user_id, username, private_key_pem

    except sqlite3.IntegrityError as e:
        print(f"Error: Registration failed. Constraint issue (e.g., username collision). ({e})")
        # traceback.print_exc() # Optional: uncomment for detailed integrity errors
        return None, None, None
    except Exception as e:
        print(f"An unexpected error occurred during registration: {e}")
        traceback.print_exc()
        return None, None, None
    finally:
        # Ensure connection is closed even if errors occurred
        if conn:
            conn.close()


def login_user(username_or_email, password, private_key_pem_bytes=None):
    """
    Attempts login using username, password, and private key file content.
    Does NOT store the private key in the session.

    Args:
        username_or_email (str): User's login identifier.
        password (str): User's plaintext password.
        private_key_pem_bytes (bytes, optional): Content of the user's private key PEM file.

    Returns:
        tuple: (user_data, None) on success, or (None, error_message) on failure.
               user_data is a dictionary containing user info, attributes, and public key.
               Private key is NOT included.
    """
    print(f"Attempting login for '{username_or_email}'...") # Okay to log username attempt
    conn = get_db_connection()
    user = None
    try:
        # Fetch user data including the stored public key
        user = conn.execute(
            """SELECT u.user_id, u.username, u.password_hash, r.role_name, u.public_key
               FROM users u JOIN roles r ON u.role_id = r.role_id
               WHERE u.username = ?""",
            (username_or_email,)
        ).fetchone()

        # 1. Check if user exists
        if not user:
            print("Login failed: Invalid username.")
            return None, "Invalid username" # Specific error

        # 2. Check password
        if not check_password(password, user['password_hash']):
            # Do NOT log the incorrect password attempt detail here
            print(f"Login failed: Incorrect password for {username_or_email}.")
            return None, "Incorrect password" # Specific error

        # 3. Verify Private Key (Required for ALL roles)
        if not private_key_pem_bytes:
            # Do NOT log key details
            print(f"Login failed: Private key file is required for login.")
            return None, "Private key file required"

        if not user['public_key']:
             # Do NOT log key details
             print(f"Login failed: No public key found in database for user {username_or_email}.")
             return None, "No public key registered for user"

        try:
            uploaded_key = RSA.import_key(private_key_pem_bytes)
            # Derive public key from the uploaded private key
            derived_public_key_pem = uploaded_key.public_key().export_key().decode('utf-8')
            stored_public_key_pem = user['public_key']

            # Normalize PEM strings to remove potential whitespace/newline differences
            normalized_derived = "\n".join(line.strip() for line in derived_public_key_pem.strip().splitlines())
            normalized_stored = "\n".join(line.strip() for line in stored_public_key_pem.strip().splitlines())

            if normalized_derived != normalized_stored:
                # Do NOT log key details
                print(f"Login failed: Private key does not match the registered public key for {username_or_email}.")
                return None, "Private key mismatch" # Specific error
            else:
                 # Okay to log verification success, but not key content
                print("Private key verified successfully.")

        except (ValueError, TypeError, IndexError, Exception) as key_e:
            # Do NOT log key details or the key_e content if it might contain sensitive info
            print(f"Login failed: Error processing private key file for {username_or_email}. Is it a valid PEM key?")
            # traceback.print_exc() # Avoid printing traceback which might show key parts
            return None, f"Invalid private key file format or content." # Generic error to user

        # If all checks pass:
        print(f"Login successful! Welcome, {user['username']} ({user['role_name']}).")

        # Fetch User Attributes
        user_attrs_rows = conn.execute(
            "SELECT attribute_name, attribute_value FROM user_attributes WHERE user_id = ?",
            (user['user_id'],)
        ).fetchall()
        user_attributes_dict = {row['attribute_name']: row['attribute_value'] for row in user_attrs_rows}

        # Combine basic user info with attributes
        user_data = dict(user) # Convert Row object to dict
        user_data['attributes'] = user_attributes_dict
        user_data['public_key_pem'] = user['public_key'] # Pass public key to session

        # --- REMOVED private key from session data ---

        return user_data, None # Success

    except sqlite3.Error as e:
        print(f"A database error occurred during login: {e}")
        traceback.print_exc() # Print traceback for DB errors
        return None, f"Database error: {e}"
    except Exception as e:
        print(f"An unexpected error occurred during login: {e}")
        # traceback.print_exc() # Avoid traceback here too
        return None, f"Unexpected server error during login." # Generic error
    finally:
        if conn:
            conn.close()
