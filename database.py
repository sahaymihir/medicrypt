import sqlite3
import os

DB_NAME = 'medicrypt.db'

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON;") # Ensure foreign keys are enforced
    conn.row_factory = sqlite3.Row  # Makes query results easier to work with
    return conn

def seed_roles():
    """
    Seeds the roles table with the essential roles.
    Run this file *once* to make sure roles are in your DB.
    """
    print("Seeding roles...")
    conn = get_db_connection()
    try:
        with conn:
            conn.executescript("""
                INSERT OR IGNORE INTO roles (role_name) VALUES ('admin');
                INSERT OR IGNORE INTO roles (role_name) VALUES ('doctor');
                INSERT OR IGNORE INTO roles (role_name) VALUES ('patient');
                INSERT OR IGNORE INTO roles (role_name) VALUES ('pharmacist');
            """)
        print("Roles table seeded successfully.")
    except sqlite3.Error as e:
        print(f"An error occurred while seeding roles: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    # If you run this file directly (e.g., "python database.py"),
    # it will seed your roles.
    if not os.path.exists(DB_NAME):
        print(f"Error: Database file '{DB_NAME}' not found.")
        print("Please make sure your database file is in the same directory.")
    else:
        seed_roles()
