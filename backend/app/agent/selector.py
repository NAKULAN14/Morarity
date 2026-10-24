
from app.models.schemas import AnalysisResult, VerificationTest


class AdaptiveTestSelector:
    """
    Selects verification tests based on the analyzer's findings
    and the security invariants that must be preserved.
    """

    def select_tests(
        self,
        analysis: AnalysisResult,
        scenario: str | None = None,
    ) -> list[VerificationTest]:

        tests: list[VerificationTest] = []

        finding_ids = {
            finding.rule_id
            for finding in analysis.findings
        }

        # Test whether SQL injection payloads are safely handled.
        if (
            "SQLI_UNSAFE_QUERY" in finding_ids
            or "SQLI_UNKNOWN_QUERY" in finding_ids
            or analysis.vulnerability_type == "SQL_INJECTION"
        ):
            tests.extend(self._sql_injection_tests())

        # If the analyzer found a parameterized query,
        # include a regression test to ensure parameterization remains.
        if "SQLI_PARAMETERIZED_QUERY" in finding_ids:
            tests.append(
                VerificationTest(
                    test_id="SQLI_REGRESSION_001",
                    name="Parameterized Query Regression",
                    description=(
                        "Check that parameterized SQL execution "
                        "continues to be used after patching."
                    ),
                    test_type="regression",
                    payload=None,
                )
            )

        # Always include a basic functionality test.
        tests.append(
            VerificationTest(
                test_id="FUNCTIONALITY_001",
                name="Basic Functionality Check",
                description=(
                    "Check that the application's expected "
                    "functionality remains intact."
                ),
                test_type="functionality",
                payload=None,
            )
        )

        # Add a scenario-specific test when a scenario is supplied.
        if scenario:
            tests.append(
                VerificationTest(
                    test_id="SCENARIO_001",
                    name="Scenario-Specific Verification",
                    description=(
                        "Verify the application behavior described "
                        "by the supplied scenario."
                    ),
                    test_type="scenario",
                    payload=scenario,
                )
            )

        # Remove duplicate test IDs while preserving order.
        unique_tests = {
            test.test_id: test
            for test in tests
        }

        return list(unique_tests.values())

    @staticmethod
    def _sql_injection_tests() -> list[VerificationTest]:
        return [
            VerificationTest(
                test_id="SQLI_NEGATIVE_001",
                name="SQL Injection Resistance",
                description=(
                    "Check whether SQL injection-style input "
                    "is treated as data rather than SQL syntax."
                ),
                test_type="security",
                payload="' OR '1'='1",
            ),
            VerificationTest(
                test_id="SQLI_NEGATIVE_002",
                name="SQL Comment Injection Resistance",
                description=(
                    "Check whether SQL comment syntax in input "
                    "can alter query behavior."
                ),
                test_type="security",
                payload="' OR 1=1 --",
            ),
        ]


def select_tests(
    analysis: AnalysisResult,
    scenario: str | None = None,
) -> list[VerificationTest]:
    """
    Convenience function for selecting tests.
    """
    return AdaptiveTestSelector().select_tests(
        analysis=analysis,
        scenario=scenario,
    )
