import hashlib

def simple_hash(password: str) -> str:
    """Simple hash function for demo purposes"""
    return hashlib.sha256(f"{password}hospital_salt".encode()).hexdigest()

def verify_simple_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using simple hash"""
    return simple_hash(plain_password) == hashed_password

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Wrapper for password verification"""
    return verify_simple_password(plain_password, hashed_password)
