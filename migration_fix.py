import sqlite3
from database import get_db_connection
import traceback

# --- Store Original CREATE Statements (Important for Recreation) ---
# It's safer to define the schemas here than rely on PRAGMA introspection
# which might read the corrupted schema.
SCHEMA = {
    "users": """
        CREATE TABLE users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role_id INTEGER NOT NULL,
            public_key TEXT, -- Only public key
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (role_id) REFERENCES roles (role_id)
        );
    """,
    "admin_profile": """
        CREATE TABLE admin_profile (
            user_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            contact_email TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE -- Point to users, ADD ON DELETE CASCADE
        );
    """,
    "user_attributes": """
        CREATE TABLE user_attributes (
            attribute_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            attribute_name TEXT NOT NULL,
            attribute_value TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE, -- Point to users, ADD ON DELETE CASCADE
            UNIQUE(user_id, attribute_name, attribute_value)
        );
    """,
    "doctor_profile": """
        CREATE TABLE doctor_profile (
            user_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            department TEXT NOT NULL,
            specialty TEXT,
            hospital_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE -- Point to users, ADD ON DELETE CASCADE
        );
    """,
    "pharmacist_profile": """
        CREATE TABLE pharmacist_profile (
            user_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            pharmacy_name TEXT,
            license_number TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE -- Point to users, ADD ON DELETE CASCADE
        );
    """,
    "patient_profile": """
        CREATE TABLE patient_profile (
            user_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            phe_age BLOB, -- Age moved here
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE -- Point to users, ADD ON DELETE CASCADE
        );
    """,
    "medical_records": """
        CREATE TABLE medical_records (
            record_id TEXT PRIMARY KEY,
            patient_user_id TEXT NOT NULL,
            record_type TEXT,
            encrypted_data BLOB, -- Changed to BLOB
            policy_str TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_by_user_id TEXT,
            phe_heart_rate BLOB,
            phe_weight BLOB,
            phe_height BLOB,
            FOREIGN KEY (patient_user_id) REFERENCES users (user_id) ON DELETE CASCADE, -- Point to users, ADD ON DELETE CASCADE
            FOREIGN KEY (created_by_user_id) REFERENCES users (user_id) ON DELETE CASCADE -- Point to users, ADD ON DELETE CASCADE
        );
    """,
     "search_index": """
        CREATE TABLE search_index (
            keyword_token TEXT NOT NULL,
            record_id TEXT NOT NULL,
            PRIMARY KEY (keyword_token, record_id),
            FOREIGN KEY (record_id) REFERENCES medical_records (record_id) ON DELETE CASCADE
        );
    """,
    "blockchain_audit_log": """
        CREATE TABLE blockchain_audit_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_hash TEXT UNIQUE NOT NULL,
            previous_hash TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            nonce TEXT,
            user_id TEXT,
            action TEXT NOT NULL,
            record_id TEXT,
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE SET NULL -- Point to users, SET NULL on delete
        );
    """
    # Note: Added ON DELETE CASCADE to most FKs for easier cleanup.
    # Set blockchain_audit_log FK to SET NULL to preserve logs even if user deleted.
    # Changed medical_records encrypted_data to BLOB as it stores bytes.
}


def recreate_table_with_correct_fk(conn, table_name, schema_sql):
    """
    Safely recreates a table to fix its schema or foreign keys.
    Assumes data has been wiped by reset_database.py, so no data copy needed.
    """
    print(f"Recreating '{table_name}' table...")
    try:
        with conn:
            # Check if table exists before dropping
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,))
            if cursor.fetchone():
                conn.execute(f"DROP TABLE {table_name};")
                print(f"- Dropped existing '{table_name}' table.")
            else:
                 print(f"- Table '{table_name}' does not exist, creating new.")
            # Create the table with the correct schema
            conn.execute(schema_sql)
            print(f"- Created new '{table_name}' table with correct foreign keys.")
        return True
    except sqlite3.Error as e:
        print(f"!!! Error recreating table '{table_name}': {e}")
        traceback.print_exc()
        return False


def run_migration():
    """
    Applies schema changes: removes private key from users and recreates
    dependent tables to fix FOREIGN KEY references.
    Also ensures necessary PHE columns exist.
    """
    print("Connecting to database to apply migration...")
    conn = get_db_connection()
    migration_successful = True

    try:
        # --- Step 1: Fix the 'users' table (Remove private_key_encrypted) ---
        cursor_users = conn.execute("PRAGMA table_info(users)")
        columns_users = {row['name']: row for row in cursor_users.fetchall()}

        users_recreated = False
        if 'private_key_encrypted' in columns_users:
            print("Recreating 'users' table to remove 'private_key_encrypted' column...")
            try:
                with conn:
                    # Rename old table
                    conn.execute("ALTER TABLE users RENAME TO users_old;")
                    # Create new table with correct schema
                    conn.execute(SCHEMA["users"])
                    # Copy data (excluding the dropped column)
                    conn.execute("""
                        INSERT INTO users (user_id, username, password_hash, role_id, public_key, created_at)
                        SELECT user_id, username, password_hash, role_id, public_key, created_at
                        FROM users_old;
                    """)
                    # Drop the old table
                    conn.execute("DROP TABLE users_old;")
                print("'users' table recreated successfully without private key storage.")
                users_recreated = True
            except sqlite3.Error as e:
                print(f"!!! Error during 'users' table recreation: {e}")
                traceback.print_exc()
                migration_successful = False
        else:
            print("'users' table already has the correct schema (no private key column).")
            # If users wasn't recreated, we assume FKs *might* be correct,
            # but it's safer to recreate dependents if they reference users_old.
            # We will check and recreate dependents regardless for robustness.

        # --- Step 2: Recreate ALL dependent tables to ensure FKs point to 'users' ---
        if migration_successful: # Only proceed if users table is likely okay
            dependent_tables = [
                "admin_profile", "user_attributes", "doctor_profile",
                "pharmacist_profile", "patient_profile", "medical_records",
                "blockchain_audit_log" # Search Index depends on medical_records, handled later
            ]
            for table in dependent_tables:
                if not recreate_table_with_correct_fk(conn, table, SCHEMA[table]):
                    migration_successful = False
                    break # Stop if one fails

        # --- Step 3: Recreate search_index (depends on medical_records) ---
        if migration_successful:
             if not recreate_table_with_correct_fk(conn, "search_index", SCHEMA["search_index"]):
                 migration_successful = False


        # --- Step 4: Verify/Add necessary columns (PHE columns) ---
        # (These ALTER TABLE commands are safe even after recreation)
        if migration_successful:
            print("Verifying necessary columns exist...")
            with conn:
                 # medical_records PHE cols (already in SCHEMA)
                 # patient_profile PHE col (already in SCHEMA)
                 # Check medical_records data type for encrypted_data
                 cursor_mr_check = conn.execute("PRAGMA table_info(medical_records)")
                 mr_cols = {row['name']: row['type'] for row in cursor_mr_check.fetchall()}
                 if mr_cols.get('encrypted_data') == 'TEXT':
                     print("WARNING: medical_records.encrypted_data column is TEXT, should be BLOB. Manual correction might be needed if data exists.")
                     # A full table recreate is the only reliable way to change type if data exists.
                     # Since reset_database was run, this shouldn't be an issue now.
            print("Column verification complete.")


        if migration_successful:
            print("\nMigration completed successfully!")
            print("Database schema is now consistent.")
        else:
            print("\nMigration failed! Please review the errors above.")
            print("Database schema might be in an inconsistent state.")


    except Exception as e:
        print(f"\nAn unexpected error occurred during migration: {e}")
        traceback.print_exc()
    finally:
        conn.close()


if __name__ == "__main__":
    run_migration()

