from pydantic import BaseModel
from typing import List

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
