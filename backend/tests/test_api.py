from app.api.routes import health_check, verify_patch
from app.models.schemas import VerificationRequest


def test_health_check_function():
    result = health_check()
    assert result["status"] == "healthy"
    assert result["service"] == "Moriarty"


def test_api_verify_function():
    source_code = """
def get_user(cursor, username):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
"""
    req = VerificationRequest(source_code=source_code)
    response = verify_patch(req)
    assert response.verification_id is not None
    assert response.verdict is not None
    assert response.analysis is not None
