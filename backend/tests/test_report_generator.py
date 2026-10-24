
import json

from app.models.schemas import (
    AnalysisResult,
    Verdict,
    VerificationResponse,
)
from app.reporting.report_generator import ReportGenerator


def test_report_generator_creates_json_report(tmp_path):
    response = VerificationResponse(
        verification_id="test-verification-001",
        verdict=Verdict.INCONCLUSIVE,
        summary="Static improvement detected, but runtime verification is incomplete.",
        analysis=AnalysisResult(
            supported=True,
            vulnerability_type="SQL Injection",
            findings=[],
            security_invariants=[
                "User input must not be concatenated into SQL queries."
            ],
            summary="SQL injection pattern analyzed.",
        ),
        tests_executed=[],
        evidence=[],
        limitations=[
            "Runtime testing has not been performed."
        ],
    )

    output_file = tmp_path / "reports" / "verification.json"

    generator = ReportGenerator()
    report = generator.generate(
        response,
        output_path=output_file,
    )

    assert report["verification_id"] == "test-verification-001"
    assert report["verdict"] == "INCONCLUSIVE"
    assert report["analysis"]["vulnerability_type"] == "SQL Injection"

    assert (
        "Runtime testing has not been performed."
        in report["limitations"]
    )

    assert output_file.exists()

    saved_report = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert saved_report["verdict"] == "INCONCLUSIVE"
