from fastapi import APIRouter, HTTPException
from app.models.schemas import VerificationRequest, VerificationResponse
from app.agent.controller import VerificationController

router = APIRouter()
controller = VerificationController()


@router.get("/health")
def health_check():
    return {"status": "healthy", "service": "Moriarty"}


@router.post("/verify", response_model=VerificationResponse)
def verify_patch(request: VerificationRequest):
    try:
        return controller.verify(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
