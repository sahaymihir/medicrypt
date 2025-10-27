import sqlite3
from database import get_db_connection

# A list of dummy medicines to add
DUMMY_MEDICINES = [
    ('Paracetamol', '500mg', 2.50),
    ('Amoxicillin', '250mg', 15.00),
    ('Atorvastatin', '20mg', 30.00),
    ('Metformin', '500mg', 8.50),
    ('Amlodipine', '5mg', 12.00),
    ('Omeprazole', '20mg', 22.00),
    ('Losartan', '50mg', 18.00),
    ('Salbutamol Inhaler', '100mcg', 50.00)
]


def seed_medicines_table():
    """
    Inserts a list of dummy medicines into the 'medicines' table.
    """
    print("Seeding 'medicines' table...")
    conn = get_db_connection()
    try:
        with conn:
            # Clear existing medicines to avoid duplicates
            conn.execute("DELETE FROM medicines;")
            conn.execute("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'medicines';")

            # Insert the new list
            conn.executemany(
                "INSERT INTO medicines (name, strength, price) VALUES (?, ?, ?)",
                DUMMY_MEDICINES
            )

        print(f"Successfully seeded {len(DUMMY_MEDICINES)} medicines.")

    except sqlite3.Error as e:
        print(f"An error occurred while seeding medicines: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    # Run this file directly to seed the medicines:
    # python seed_medicines.py
    seed_medicines_table()
