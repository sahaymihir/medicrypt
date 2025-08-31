import sqlite3
import hashlib
import json
from datetime import datetime, timezone, timedelta # Import timezone and timedelta
import traceback # Import traceback

# CORRECTED: Use absolute import
from database import get_db_connection

# Define known action types (optional, but good practice)
ACTION_LOGIN_SUCCESS = 'LOGIN_SUCCESS'
ACTION_LOGIN_FAILURE = 'LOGIN_FAILURE'
ACTION_LOGOUT = 'LOGOUT'
ACTION_CREATE_PRESCRIPTION = 'CREATE_PRESCRIPTION'
ACTION_ADMIN_CREATE_USER_SUCCESS = 'ADMIN_CREATE_USER_SUCCESS'
ACTION_ADMIN_CREATE_USER_FAILED = 'ADMIN_CREATE_USER_FAILED'
ACTION_RUN_STATISTICS = 'RUN_STATISTICS' # Generic stats action
ACTION_RUN_CONDITIONAL_STATISTICS = 'RUN_CONDITIONAL_STATISTICS' # Generic stats action
ACTION_RUN_AGE_BY_DIAGNOSIS_STATISTICS = 'RUN_AGE_BY_DIAGNOSIS_STATISTICS' # Generic stats action
ACTION_DOCTOR_KEYWORD_SEARCH = 'DOCTOR_KEYWORD_SEARCH' # Specific search action
# --- ADDED STATS ACTIONS ---
ACTION_DOCTOR_RUN_BP_STATS = 'DOCTOR_RUN_BP_STATS'
ACTION_DOCTOR_RUN_PULSE_STATS = 'DOCTOR_RUN_PULSE_STATS'
# --- END ADDED ---
ACTION_PHARMACIST_DISPENSE = 'PHARMACIST_DISPENSE' # Dispensing action
ACTION_ERROR = 'ERROR' # Generic error logging


def get_last_block_hash(conn): # Pass connection
    """Helper function to get the hash of the most recent block."""
    try:
        cursor = conn.execute("SELECT block_hash FROM blockchain_audit_log ORDER BY log_id DESC LIMIT 1")
        last_hash_row = cursor.fetchone()
        if last_hash_row:
            return last_hash_row['block_hash']
        else:
            # Genesis block hash
            return "0" * 64
    except sqlite3.Error as e:
        print(f"Error getting last block hash: {e}")
        # traceback.print_exc() # Optional traceback
        return "0" * 64 # Default on error


def calculate_block_hash(previous_hash, timestamp_str, user_id, action, record_id, details):
    """Calculates the hash for a new block including a precise timestamp."""
    block_data = {
        "previous_hash": previous_hash,
        "timestamp": timestamp_str, # Use the generated timestamp string
        "user_id": user_id or "System", # Handle None user_id
        "action": action,
        "record_id": record_id or "N/A", # Handle None record_id
        "details": details or "" # Handle None or empty details
    }
    # Use sort_keys and separators for compact, deterministic JSON
    block_string = json.dumps(block_data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(block_string.encode('utf-8')).hexdigest()


def log_action_to_blockchain(user_id, action, record_id=None, details=""):
    """Creates a new block in the audit log table with chained hashes and IST timestamp."""
    # --- Check for known action types ---
    known_actions = {
        ACTION_LOGIN_SUCCESS, ACTION_LOGIN_FAILURE, ACTION_LOGOUT,
        ACTION_CREATE_PRESCRIPTION, ACTION_ADMIN_CREATE_USER_SUCCESS,
        ACTION_ADMIN_CREATE_USER_FAILED, ACTION_RUN_STATISTICS,
        ACTION_RUN_CONDITIONAL_STATISTICS, ACTION_RUN_AGE_BY_DIAGNOSIS_STATISTICS,
        ACTION_DOCTOR_KEYWORD_SEARCH,
        # --- UPDATED STATS ACTIONS ---
        ACTION_DOCTOR_RUN_BP_STATS,
        ACTION_DOCTOR_RUN_PULSE_STATS,
        # --- END UPDATE ---
        ACTION_PHARMACIST_DISPENSE, # Added pharmacist action
        ACTION_ERROR
    }
    if action not in known_actions:
        print(f"Warning: Logging unknown action type '{action}'")
    # --- END CHECK ---

    print(f"Logging action to blockchain: {action} by {user_id or 'System'}")
    conn = None # Initialize conn outside try
    try:
        conn = get_db_connection()
        # 1. Get the hash of the previous block
        previous_hash = get_last_block_hash(conn)

        # 2. Get current timestamp IN IST
        ist_offset = timedelta(hours=5, minutes=30)
        ist_tz = timezone(ist_offset, name='IST')
        now_utc = datetime.now(timezone.utc)
        now_ist = now_utc.astimezone(ist_tz)
        timestamp_str = now_ist.isoformat()

        # 3. Calculate the hash for this new block using the IST timestamp string
        block_hash = calculate_block_hash(previous_hash, timestamp_str, user_id, action, record_id, details)

        # 4. Insert the new block into the chain
        with conn:
            conn.execute(
                """
                INSERT INTO blockchain_audit_log
                    (block_hash, previous_hash, timestamp, user_id, action, record_id, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (block_hash, previous_hash, timestamp_str, user_id, action, record_id, details)
            )
        print(f"Successfully logged block (IST): {block_hash[:12]}...")
        return True

    except sqlite3.Error as e:
        print(f"!!! Database error logging to blockchain: {e}")
        traceback.print_exc() # Print full traceback for DB errors
        return False
    except Exception as e:
        print(f"!!! Unexpected error during blockchain logging: {e}")
        traceback.print_exc() # Print full traceback for other errors
        return False
    finally:
        if conn:
            conn.close()


def check_if_dispensed(record_id):
    """Checks the blockchain log to see if a PHARMACIST_DISPENSE action exists for a record."""
    print(f"Checking blockchain if record {record_id} is dispensed...")
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.execute(
            "SELECT 1 FROM blockchain_audit_log WHERE record_id = ? AND action = ? LIMIT 1",
            (record_id, ACTION_PHARMACIST_DISPENSE)
        )
        dispensed = cursor.fetchone() is not None
        print(f"Blockchain check result for {record_id}: {'Dispensed' if dispensed else 'Not Dispensed'}")
        return dispensed
    except sqlite3.Error as e:
        print(f"Error checking blockchain for dispense status: {e}")
        traceback.print_exc()
        return False # Assume not dispensed if error occurs, though this could be risky
    except Exception as e:
        print(f"Unexpected error during dispense check: {e}")
        traceback.print_exc()
        return False
    finally:
        if conn:
            conn.close()
