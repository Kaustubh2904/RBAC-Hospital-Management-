from fastapi import APIRouter, Depends, HTTPException
from models import RecordResponse, StatusUpdate, PrescriptionCreate
from auth import require_permission
from database import get_user_by_id, get_patient_records, update_record_status, create_prescription

router = APIRouter(prefix="/records", tags=["Medical Records"])

@router.get("/{patient_id}", response_model=RecordResponse)
def get_medical_records(
    patient_id: int, 
    current_user: dict = Depends(require_permission("view_records"))
):
    """View medical records"""
    # Patients can only view their own records
    if current_user["role"] == "Patient" and current_user["id"] != patient_id:
        raise HTTPException(status_code=403, detail="Patients can only access their own records")
    
    # Check if patient exists
    patient = get_user_by_id(patient_id)
    if not patient or patient["role"] != "Patient":
        raise HTTPException(status_code=404, detail="Patient not found")
    
    # Get records
    records = get_patient_records(patient_id)
    
    return RecordResponse(patient_id=patient_id, records=records)

@router.patch("/{patient_id}/status", status_code=204)
def update_patient_status(
    patient_id: int,
    status_update: StatusUpdate,
    current_user: dict = Depends(require_permission("update_status"))
):
    """Update patient status (Nurse/Doctor only)"""
    # Check if patient exists
    patient = get_user_by_id(patient_id)
    if not patient or patient["role"] != "Patient":
        raise HTTPException(status_code=404, detail="Patient not found")
    
    update_record_status(patient_id, status_update.status)

@router.post("/{patient_id}/prescriptions", status_code=201)
def prescribe_medication(
    patient_id: int,
    prescription: PrescriptionCreate,
    current_user: dict = Depends(require_permission("prescribe_medication"))
):
    """Prescribe medication (Doctor only)"""
    # Check if patient exists
    patient = get_user_by_id(patient_id)
    if not patient or patient["role"] != "Patient":
        raise HTTPException(status_code=404, detail="Patient not found")
    
    # Create prescription
    new_prescription = create_prescription(
        patient_id, 
        prescription.medication, 
        prescription.dosage, 
        current_user["id"]
    )
    
    return new_prescription
