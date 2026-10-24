
from app.execution.runner import run_tests
from app.models.schemas import VerificationTest


def test_sql_injection_payload_is_treated_as_data():
    test = VerificationTest(
        test_id="SQLI_NEGATIVE_001",
        name="SQL Injection Resistance",
        description="Test parameterized query behavior.",
        test_type="security",
        payload="' OR '1'='1",
    )

    results = run_tests([test])

    assert len(results) == 1
    assert results[0].passed is True
    assert results[0].outcome == "PASS"


def test_comment_injection_payload_is_treated_as_data():
    test = VerificationTest(
        test_id="SQLI_NEGATIVE_002",
        name="SQL Comment Injection Resistance",
        description="Test SQL comment input behavior.",
        test_type="security",
        payload="' OR 1=1 --",
    )

    results = run_tests([test])

    assert results[0].passed is True
    assert results[0].outcome == "PASS"


def test_unsupported_test_type():
    test = VerificationTest(
        test_id="FUNCTIONALITY_001",
        name="Functionality Check",
        description="Check basic functionality.",
        test_type="functionality",
    )

    results = run_tests([test])

    assert results[0].passed is False
    assert results[0].outcome == "NOT_SUPPORTED"


def test_runner_returns_execution_time():
    test = VerificationTest(
        test_id="SQLI_NEGATIVE_001",
        name="SQL Injection Resistance",
        description="Test parameterized query behavior.",
        test_type="security",
        payload="' OR '1'='1",
    )

    results = run_tests([test])

    assert results[0].execution_time_ms is not None
    assert results[0].execution_time_ms >= 0
