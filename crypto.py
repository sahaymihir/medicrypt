import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import binascii
import pickle  # For serializing PHE objects
import traceback # Import traceback

# --- NEW IMPORTS for Digital Signatures (RSA) ---
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# --- NEW IMPORTS for Homomorphic Encryption (PHE) ---
import phe.paillier as paillier

# --- NEW IMPORTS for SSE ---
import hmac
import hashlib

# --- Constants ---
SECRET_KEY_FILE = 'medcrypt_master.key'
PHE_PUBLIC_KEY_FILE = 'phe_public.key'
PHE_PRIVATE_KEY_FILE = 'phe_private.key'


# --- AES Key Management ---

def get_master_key():
    """
    Loads the master key from its file, or creates one if it doesn't exist.
    This key is used for HMAC (in SSE) and KDF (in AES).
    """
    if not os.path.exists(SECRET_KEY_FILE):
        print(f"Generating new master key... DO NOT LOSE THIS FILE.")
        master_key = get_random_bytes(32)
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(master_key)
        return master_key
    else:
        with open(SECRET_KEY_FILE, 'rb') as f:
            return f.read()


def get_data_encryption_key(salt):
    """Derives a data encryption key from the master key using PBKDF2."""
    master_key = get_master_key()
    # KDF to derive a unique AES key for each record
    key = PBKDF2(master_key, salt, 32, count=1000000, hmac_hash_module=SHA256)
    return key


# --- AES Encryption Functions ---

def encrypt_record_aes(data_bytes, policy_str):
    """
    Encrypts data using AES-CBC with a derived key.
    Prepends the salt and IV to the ciphertext.
    """
    try:
        salt = get_random_bytes(16)
        aes_key = get_data_encryption_key(salt)
        cipher = AES.new(aes_key, AES.MODE_CBC)  # CBC mode with random IV
        ciphertext_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
        iv = cipher.iv

        # Combine salt, IV, and ciphertext, separated by ':'
        encrypted_data_hex = f"{salt.hex()}:{iv.hex()}:{ciphertext_bytes.hex()}"

        # Return as bytes (to store in BLOB) and the policy string
        return encrypted_data_hex.encode('utf-8'), policy_str
    except Exception as e:
        print(f"Error in encrypt_record_aes: {e}")
        traceback.print_exc() # Print traceback for encryption errors
        return None, None


def decrypt_record_aes(encrypted_data_hex_str, user_attributes, policy_str):
    """
    Checks if user_attributes satisfy the policy_str, then decrypts.
    """
    print("\n--- Policy Check ---") # Debug Start
    print(f"Policy: {policy_str}")
    print(f"User Attributes: {user_attributes}")

    try:
        # 1. Check Policy
        policy_groups = policy_str.split(' OR ')
        group_satisfied = False
        for group in policy_groups:
            # --- FIX: Strip leading/trailing whitespace AND parentheses from the group ---
            processed_group = group.strip()
            if processed_group.startswith('(') and processed_group.endswith(')'):
                processed_group = processed_group[1:-1].strip() # Remove outer parentheses
            # --- END FIX ---

            print(f"  Checking group: {group} -> Conditions: {processed_group.split(' AND ')}") # Debug
            conditions = processed_group.split(' AND ')
            conditions_met = True
            for part in conditions:
                part = part.strip() # Strip whitespace from individual conditions
                if ":" not in part:
                    print(f"    Malformed condition part: '{part}'") # Debug
                    conditions_met = False
                    break
                key, value = part.split(':', 1)
                key = key.strip() # Strip whitespace from key
                value = value.strip() # Strip whitespace from value

                user_value = user_attributes.get(key)
                print(f"    Checking condition: '{key}' == '{value}'? User has: '{user_value}'") # Debug
                # Check if the user has this attribute with this value
                if user_value != value: # Direct string comparison
                    print("      Mismatch.") # Debug
                    conditions_met = False
                    break
                else:
                     print("      Match.") # Debug


            if conditions_met:
                print("  Group satisfied.") # Debug
                group_satisfied = True
                break
            else:
                 print("  Group NOT satisfied.") # Debug

        print("--- End Policy Check ---") # Debug End

        if not group_satisfied:
            print(f"Decryption failed: User attributes do not match policy.") # Keep concise error
            return None

        # 2. Decrypt Data (If policy check passed)
        salt_hex, iv_hex, ciphertext_hex = encrypted_data_hex_str.split(':')
        salt = bytes.fromhex(salt_hex)
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)

        aes_key = get_data_encryption_key(salt)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return decrypted_bytes

    except (ValueError, KeyError, binascii.Error) as e:
        print(f"Decryption failed (bad key, data split error, or corrupted data): {e}")
        # traceback.print_exc() # Optional: Add traceback here if needed
        return None
    except Exception as e:
        print(f"Generic decryption error: {e}")
        traceback.print_exc() # Print traceback for unexpected errors
        return None


# --- NEW: Searchable Symmetric Encryption (SSE) ---

def generate_sse_token(keyword):
    """
    Generates a secure, deterministic token for a given keyword
    using HMAC-SHA256 with the master key.
    """
    master_key = get_master_key()
    # Normalize keyword to ensure "Heart Disease" and "heart disease" produce the same token
    processed_keyword = keyword.lower().strip().encode('utf-8')
    token = hmac.new(master_key, processed_keyword, hashlib.sha256).hexdigest()
    return token


# --- Digital Signature (RSA) Functions ---

def generate_rsa_keys():
    """Generates a new 2048-bit RSA key pair."""
    key = RSA.generate(2048)
    # Export keys in PKCS#8 (private) and SubjectPublicKeyInfo (public) formats
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def sign_data(private_key_pem, data_bytes):
    """Signs a byte string using a private key."""
    try:
        key = RSA.import_key(private_key_pem)
        h = SHA256.new(data_bytes)  # Create hash of the data
        signature = pkcs1_15.new(key).sign(h)
        return signature
    except Exception as e:
        print(f"Error during signing: {e}")
        traceback.print_exc() # Print traceback for signing errors
        return None


def verify_signature(public_key_pem, data_bytes, signature_bytes):
    """Verifies a signature against data and a public key."""
    try:
        key = RSA.import_key(public_key_pem)
        h = SHA256.new(data_bytes)
        pkcs1_15.new(key).verify(h, signature_bytes)
        print("Signature verified successfully.") # Debug
        return True  # Verification successful
    except (ValueError, TypeError) as e:
        print(f"Signature verification failed (ValueError/TypeError): {e}") # Debug specific error
        # traceback.print_exc() # Optional traceback
        return False
    except Exception as e:
        print(f"Signature verification failed (Other Exception): {e}") # Debug specific error
        # traceback.print_exc() # Optional traceback
        return False


# --- Homomorphic Encryption (PHE) Functions ---

def get_phe_keys():
    """
    Loads Paillier keys from files, or creates them if they don't exist.
    Uses pickle to store the key objects.
    """
    if not os.path.exists(PHE_PUBLIC_KEY_FILE) or not os.path.exists(PHE_PRIVATE_KEY_FILE):
        print("Generating new PHE key pair (this may take a moment)...")
        # Generate a 1024-bit key pair
        public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)

        with open(PHE_PUBLIC_KEY_FILE, 'wb') as f:
            pickle.dump(public_key, f)
        with open(PHE_PRIVATE_KEY_FILE, 'wb') as f:
            pickle.dump(private_key, f)

        print("PHE keys generated and saved.")
        return public_key, private_key
    else:
        # Load existing keys
        with open(PHE_PUBLIC_KEY_FILE, 'rb') as f:
            public_key = pickle.load(f)
        with open(PHE_PRIVATE_KEY_FILE, 'rb') as f:
            private_key = pickle.load(f)
        # print("PHE keys loaded from files.") # Optional: uncomment for confirmation
        return public_key, private_key


def phe_encrypt(public_key, value):
    """Encrypts a single integer using the Paillier public key and pickles the result."""
    try:
        encrypted_value = public_key.encrypt(value)
        # Pickle the EncryptedNumber object to bytes for DB storage
        return pickle.dumps(encrypted_value)
    except Exception as e:
        print(f"Error during PHE encryption: {e}")
        traceback.print_exc() # Print traceback for PHE errors
        return None


def phe_decrypt(private_key, encrypted_value_input, deserialize_only=False):
    """
    Decrypts or deserializes a PHE value.

    This function can accept EITHER pickled bytes (from DB) OR an
    in-memory EncryptedNumber object (from a sum() operation).
    """
    try:
        encrypted_value = None

        # Check if input is bytes (from DB) or an object (from sum())
        if isinstance(encrypted_value_input, bytes):
            encrypted_value = pickle.loads(encrypted_value_input)
        elif isinstance(encrypted_value_input, paillier.EncryptedNumber):
            encrypted_value = encrypted_value_input
        else:
            # If input is None or a bad type, raise an error
            raise TypeError(f"Input must be bytes or EncryptedNumber, not {type(encrypted_value_input)}")

        if deserialize_only:
            return encrypted_value
        else:
            # Decrypt the EncryptedNumber object
            return private_key.decrypt(encrypted_value)

    except Exception as e:
        print(f"Error during PHE decryption/deserialization: {e}")
        # traceback.print_exc() # Optional: Add traceback here if needed for PHE decrypt errors
        return None  # Return None on any failure

