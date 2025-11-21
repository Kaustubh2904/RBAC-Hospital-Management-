from fastapi import FastAPI
from config import API_TITLE, API_VERSION, HOST, PORT
from database import init_database
from auth import jwt_middleware
from routers import auth_router, records_router, users_router

app = FastAPI(title=API_TITLE, version=API_VERSION)

# Initialize database on startup
init_database()

# Add middleware
app.middleware("http")(jwt_middleware)

# Include routers
app.include_router(auth_router.router)
app.include_router(records_router.router)
app.include_router(users_router.router)

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
    uvicorn.run(app, host=HOST, port=PORT, reload=True)
