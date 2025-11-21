from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
import hashlib
import json
import sqlite3
from contextlib import contextmanager

# Configuration
SECRET_KEY = "hospital-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Security - Simple hashing for demo purposes
def simple_hash(password: str) -> str:
    """Simple hash function for demo purposes"""
    return hashlib.sha256(f"{password}hospital_salt".encode()).hexdigest()

def verify_simple_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using simple hash"""
    return simple_hash(plain_password) == hashed_password

security = HTTPBearer()

# SQLite Database setup
DATABASE_PATH = "hospital.db"

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

def authenticate_user(username: str, password: str):
    """Authenticate user against SQLite database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and verify_password(password, user["password_hash"]):
            return dict(user)
        return None

def get_user_by_id(user_id: int):
    """Get user by ID from database"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None

# Role permissions
ROLE_PERMISSIONS = {
    "Patient": ["view_records"],
    "Nurse": ["view_records", "update_status"],
    "Doctor": ["view_records", "update_status", "prescribe_medication"],
    "Administrator": ["view_records", "update_status", "prescribe_medication", "manage_users"]
}

app = FastAPI(title="Hospital Management System", version="1.0.0")

# Initialize database on startup
init_database()

# Models
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600

class RecordResponse(BaseModel):
    patient_id: int
    records: List[dict]

class StatusUpdate(BaseModel):
    status: str

class PrescriptionCreate(BaseModel):
    medication: str
    dosage: str

class UserCreate(BaseModel):
    username: str
    role: str
    password: str

# Auth functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return verify_simple_password(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
        user = get_user_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user["permissions"] = ROLE_PERMISSIONS.get(user["role"], [])
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_permission(permission: str):
    def check_permission(current_user: dict = Depends(get_current_user)):
        if permission not in current_user["permissions"]:
            raise HTTPException(status_code=403, detail=f"Permission required: {permission}")
        return current_user
    return check_permission

# JWT Middleware
@app.middleware("http")
async def jwt_middleware(request: Request, call_next):
    """JWT Authentication Middleware"""
    # Skip auth for public endpoints
    public_paths = ["/", "/docs", "/openapi.json", "/auth/login"]
    
    if request.url.path in public_paths or request.method == "OPTIONS":
        response = await call_next(request)
        return response
    
    # Check for Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = auth_header.split(" ")[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
        user = get_user_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Add user info to request state
        request.state.current_user = user
        request.state.current_user["permissions"] = ROLE_PERMISSIONS.get(user["role"], [])
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    response = await call_next(request)
    return response

# Authentication endpoint
@app.post("/auth/login", response_model=TokenResponse)
def login(request: LoginRequest):
    """Authenticate user and return JWT token"""
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": str(user["id"]), "role": user["role"]})
    return TokenResponse(access_token=access_token)

# Medical Records endpoints
@app.get("/records/{patient_id}", response_model=RecordResponse)
def get_medical_records(
    patient_id: int, 
    current_user: dict = Depends(require_permission("view_records"))
):
    """View medical records"""
    # Patients can only view their own records
    if current_user["role"] == "Patient" and current_user["id"] != patient_id:
        raise HTTPException(status_code=403, detail="Patients can only access their own records")
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if patient exists
        cursor.execute("SELECT role FROM users WHERE id = ?", (patient_id,))
        patient = cursor.fetchone()
        if not patient or patient["role"] != "Patient":
            raise HTTPException(status_code=404, detail="Patient not found")
        
        # Get records
        cursor.execute("SELECT * FROM records WHERE patient_id = ?", (patient_id,))
        records = [dict(row) for row in cursor.fetchall()]
        
        return RecordResponse(patient_id=patient_id, records=records)

@app.patch("/records/{patient_id}/status", status_code=204)
def update_patient_status(
    patient_id: int,
    status_update: StatusUpdate,
    current_user: dict = Depends(require_permission("update_status"))
):
    """Update patient status (Nurse/Doctor only)"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if patient exists
        cursor.execute("SELECT role FROM users WHERE id = ?", (patient_id,))
        patient = cursor.fetchone()
        if not patient or patient["role"] != "Patient":
            raise HTTPException(status_code=404, detail="Patient not found")
        
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
                (status_update.status, latest_record["id"])
            )
        else:
            # Create new record
            cursor.execute('''
                INSERT INTO records (patient_id, data, status) 
                VALUES (?, ?, ?)
            ''', (patient_id, "Status updated", status_update.status))
        
        conn.commit()

@app.post("/records/{patient_id}/prescriptions", status_code=201)
def prescribe_medication(
    patient_id: int,
    prescription: PrescriptionCreate,
    current_user: dict = Depends(require_permission("prescribe_medication"))
):
    """Prescribe medication (Doctor only)"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if patient exists
        cursor.execute("SELECT role FROM users WHERE id = ?", (patient_id,))
        patient = cursor.fetchone()
        if not patient or patient["role"] != "Patient":
            raise HTTPException(status_code=404, detail="Patient not found")
        
        # Insert prescription
        cursor.execute('''
            INSERT INTO prescriptions (patient_id, medication, dosage, prescribed_by) 
            VALUES (?, ?, ?, ?)
        ''', (patient_id, prescription.medication, prescription.dosage, current_user["id"]))
        
        prescription_id = cursor.lastrowid
        conn.commit()
        
        # Return the created prescription
        cursor.execute("SELECT * FROM prescriptions WHERE id = ?", (prescription_id,))
        new_prescription = dict(cursor.fetchone())
        
        return new_prescription

# User Management endpoints
@app.post("/users", status_code=201)
def create_user(
    user_data: UserCreate,
    current_user: dict = Depends(require_permission("manage_users"))
):
    """Create user accounts (Administrator only)"""
    valid_roles = ["Patient", "Nurse", "Doctor", "Administrator"]
    if user_data.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        try:
            hashed_password = simple_hash(user_data.password)
            cursor.execute('''
                INSERT INTO users (username, password_hash, role) 
                VALUES (?, ?, ?)
            ''', (user_data.username, hashed_password, user_data.role))
            
            new_id = cursor.lastrowid
            conn.commit()
            
            return {
                "id": new_id,
                "username": user_data.username,
                "role": user_data.role,
                "created_at": datetime.now().isoformat()
            }
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Username already exists")

@app.get("/users/me")
def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user info"""
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "role": current_user["role"],
        "permissions": current_user["permissions"]
    }

# Root endpoint
@app.get("/")
def root():
    return {
        "message": "Hospital Management System API",
        "docs": "/docs",
        "endpoints": {
            "login": "POST /auth/login",
            "view_records": "GET /records/{patient_id}",
            "update_status": "PATCH /records/{patient_id}/status",
            "prescribe": "POST /records/{patient_id}/prescriptions",
            "create_user": "POST /users",
            "current_user": "GET /users/me"
        },
        "default_users": {
            "admin": "admin123",
            "doctor1": "doctor123", 
            "nurse1": "nurse123",
            "patient1": "patient123"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
