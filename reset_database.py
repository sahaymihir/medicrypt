import sqlite3
from database import get_db_connection

def clear_all_data():
    """
    Deletes ALL data from user, profile, record, and log tables,
    leaving only the schemas and the 'roles' table data.
    """
    print("WARNING: This will delete ALL data except roles. Proceeding...")
    conn = get_db_connection()

    tables_to_clear = [
        'search_index',         # Clear before medical_records due to FK
        'medical_records',      # Clear before users due to FKs
        'blockchain_audit_log', # Clear before users due to FK
        'user_attributes',      # Clear before users due to FK
        'doctor_profile',       # Clear before users due to FK
        'patient_profile',      # Clear before users due to FK
        'pharmacist_profile',   # Clear before users due to FK
        'admin_profile',        # Clear before users due to FK
        'users',                # Clear after dependent tables
        'medicines'             # Clear medicines list
    ]

    try:
        with conn:
            for table in tables_to_clear:
                print(f"Deleting data from {table}...")
                conn.execute(f"DELETE FROM {table};")

            # Also reset sequences if they exist (for tables like medicines)
            try:
                conn.execute("DELETE FROM sqlite_sequence WHERE name = 'medicines';")
                conn.execute("DELETE FROM sqlite_sequence WHERE name = 'blockchain_audit_log';")
                conn.execute("DELETE FROM sqlite_sequence WHERE name = 'user_attributes';")
                # Add others if needed
            except sqlite3.OperationalError:
                print("Note: sqlite_sequence table might not exist or clearing sequence failed (can be ignored).")


        print("\nAll specified table data has been deleted.")

    except sqlite3.Error as e:
        print(f"\nAn error occurred while clearing data: {e}.")
    finally:
        conn.close()


if __name__ == "__main__":
    # Run this file directly to wipe the data:
    # python reset_database.py
    clear_all_data()
