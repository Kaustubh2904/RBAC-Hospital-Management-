from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime
import sqlite3
from models import UserCreate
from auth import require_permission, get_current_user
from database import create_user
from security import simple_hash

router = APIRouter(prefix="/users", tags=["User Management"])

@router.post("/", status_code=201)
def create_user_account(
    user_data: UserCreate,
    current_user: dict = Depends(require_permission("manage_users"))
):
    """Create user accounts (Administrator only)"""
    valid_roles = ["Patient", "Nurse", "Doctor", "Administrator"]
    if user_data.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")
    
    try:
        hashed_password = simple_hash(user_data.password)
        new_id = create_user(user_data.username, hashed_password, user_data.role)
        
        return {
            "id": new_id,
            "username": user_data.username,
            "role": user_data.role,
            "created_at": datetime.now().isoformat()
        }
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")

@router.get("/me")
def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user info"""
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "role": current_user["role"],
        "permissions": current_user["permissions"]
    }
