
from app.agent.selector import select_tests
from app.models.schemas import (
    AnalysisFinding,
    AnalysisResult,
    FindingSeverity,
)


def make_analysis(rule_ids: list[str]) -> AnalysisResult:
    findings = [
        AnalysisFinding(
            rule_id=rule_id,
            message=f"Test finding for {rule_id}",
            severity=FindingSeverity.HIGH,
        )
        for rule_id in rule_ids
    ]

    return AnalysisResult(
        supported=True,
        vulnerability_type="SQL_INJECTION",
        findings=findings,
        security_invariants=[],
        summary="Test analysis",
    )


def test_selects_sql_injection_tests():
    analysis = make_analysis(["SQLI_UNSAFE_QUERY"])

    tests = select_tests(analysis)

    test_ids = {test.test_id for test in tests}

    assert "SQLI_NEGATIVE_001" in test_ids
    assert "SQLI_NEGATIVE_002" in test_ids


def test_selects_functionality_test():
    analysis = make_analysis([])

    tests = select_tests(analysis)

    assert any(
        test.test_type == "functionality"
        for test in tests
    )


def test_selects_scenario_test():
    analysis = make_analysis([])

    tests = select_tests(
        analysis,
        scenario="User login should continue to work",
    )

    assert any(
        test.test_type == "scenario"
        for test in tests
    )


def test_removes_duplicate_test_ids():
    analysis = make_analysis(
        ["SQLI_UNSAFE_QUERY", "SQLI_UNKNOWN_QUERY"]
    )

    tests = select_tests(analysis)
    test_ids = [test.test_id for test in tests]

    assert len(test_ids) == len(set(test_ids))
