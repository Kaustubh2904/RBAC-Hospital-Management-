import sqlite3
from contextlib import contextmanager
from config import DATABASE_PATH
from security import simple_hash

def init_database():
    """Initialize SQLite database with tables"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    
    # Records table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES users(id)
        )
    ''')
    
    # Prescriptions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            medication TEXT NOT NULL,
            dosage TEXT NOT NULL,
            prescribed_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (prescribed_by) REFERENCES users(id)
        )
    ''')
    
    # Insert default users if not exists
    default_users = [
        ("admin", simple_hash("admin123"), "Administrator"),
        ("doctor1", simple_hash("doctor123"), "Doctor"),
        ("nurse1", simple_hash("nurse123"), "Nurse"),
        ("patient1", simple_hash("patient123"), "Patient")
    ]
    
    for username, password_hash, role in default_users:
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password_hash, role) 
            VALUES (?, ?, ?)
        ''', (username, password_hash, role))
    
    # Insert default record for patient (ID will be 4 based on insertion order)
    cursor.execute('''
        INSERT OR IGNORE INTO records (patient_id, data, status) 
        VALUES (4, "Patient medical history and current condition", "Active")
    ''')
    
    conn.commit()
    conn.close()

@contextmanager
def get_db():
    """Database connection context manager"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Enable dict-like access
    try:
        yield conn
    finally:
        conn.close()

def get_user_by_username(username: str):
    """Get user by username from database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        return dict(user) if user else None

def get_user_by_id(user_id: int):
    """Get user by ID from database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None

def create_user(username: str, password_hash: str, role: str):
    """Create a new user in the database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, role) 
            VALUES (?, ?, ?)
        ''', (username, password_hash, role))
        
        new_id = cursor.lastrowid
        conn.commit()
        return new_id

def get_patient_records(patient_id: int):
    """Get all records for a patient"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM records WHERE patient_id = ?", (patient_id,))
        return [dict(row) for row in cursor.fetchall()]

def update_record_status(patient_id: int, status: str):
    """Update the status of the most recent record for a patient"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get the most recent record
        cursor.execute(
            "SELECT id FROM records WHERE patient_id = ? ORDER BY created_at DESC LIMIT 1", 
            (patient_id,)
        )
        latest_record = cursor.fetchone()
        
        if latest_record:
            # Update existing record
            cursor.execute(
                "UPDATE records SET status = ? WHERE id = ?", 
                (status, latest_record["id"])
            )
        else:
            # Create new record
            cursor.execute('''
                INSERT INTO records (patient_id, data, status) 
                VALUES (?, ?, ?)
            ''', (patient_id, "Status updated", status))
        
        conn.commit()

def create_prescription(patient_id: int, medication: str, dosage: str, prescribed_by: int):
    """Create a new prescription"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO prescriptions (patient_id, medication, dosage, prescribed_by) 
            VALUES (?, ?, ?, ?)
        ''', (patient_id, medication, dosage, prescribed_by))
        
        prescription_id = cursor.lastrowid
        conn.commit()
        
        # Return the created prescription
        cursor.execute("SELECT * FROM prescriptions WHERE id = ?", (prescription_id,))
        return dict(cursor.fetchone())
