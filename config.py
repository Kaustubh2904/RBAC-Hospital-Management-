# Configuration settings for the Hospital Management System

# JWT Configuration
SECRET_KEY = "hospital-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Database Configuration
DATABASE_PATH = "hospital.db"

# Role permissions mapping
ROLE_PERMISSIONS = {
    "Patient": ["view_records"],
    "Nurse": ["view_records", "update_status"],
    "Doctor": ["view_records", "update_status", "prescribe_medication"],
    "Administrator": ["view_records", "update_status", "prescribe_medication", "manage_users"]
}

# API Configuration
API_TITLE = "Hospital Management System"
API_VERSION = "1.0.0"
HOST = "127.0.0.1"
PORT = 8000
