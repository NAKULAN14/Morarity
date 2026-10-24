from app.agent.controller import VerificationController
from app.models.schemas import VerificationRequest

source_code = """
cursor.execute(
    "SELECT * FROM users WHERE name = ?",
    (name,)
)
"""

request = VerificationRequest(source_code=source_code)

response = VerificationController().verify(request)

print("Verdict:", response.verdict)
print("Summary:", response.summary)
print("Tests executed:", len(response.tests_executed))
print("Evidence collected:", len(response.evidence))