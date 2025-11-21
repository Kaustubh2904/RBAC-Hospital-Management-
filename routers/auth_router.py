from fastapi import APIRouter, HTTPException
from models import LoginRequest, TokenResponse
from auth import authenticate_user, create_access_token

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest):
    """Authenticate user and return JWT token"""
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": str(user["id"]), "role": user["role"]})
    return TokenResponse(access_token=access_token)
