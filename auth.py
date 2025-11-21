from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
from jose import JWTError, jwt
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, ROLE_PERMISSIONS
from database import get_user_by_id, get_user_by_username
from security import verify_password

security = HTTPBearer()

def authenticate_user(username: str, password: str):
    """Authenticate user against SQLite database"""
    user = get_user_by_username(username)
    if user and verify_password(password, user["password_hash"]):
        return user
    return None

def create_access_token(data: dict):
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
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
    """Decorator to require specific permission"""
    def check_permission(current_user: dict = Depends(get_current_user)):
        if permission not in current_user["permissions"]:
            raise HTTPException(status_code=403, detail=f"Permission required: {permission}")
        return current_user
    return check_permission

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
