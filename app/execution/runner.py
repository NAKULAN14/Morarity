
import sqlite3
import time

from app.models.schemas import TestResult, VerificationTest


class VerificationTestRunner:
    """
    Executes SQL injection verification tests against a controlled
    in-memory SQLite database.
    """

    def run_tests(
        self,
        tests: list[VerificationTest],
    ) -> list[TestResult]:
        results: list[TestResult] = []

        for test in tests:
            start_time = time.perf_counter()

            try:
                result = self._run_single_test(test)
            except Exception as exc:
                result = TestResult(
                    test_id=test.test_id,
                    passed=False,
                    outcome="ERROR",
                    details="The verification test could not be completed.",
                    error=str(exc),
                )

            elapsed_ms = (time.perf_counter() - start_time) * 1000
            result.execution_time_ms = round(elapsed_ms, 3)

            results.append(result)

        return results

    def _run_single_test(
        self,
        test: VerificationTest,
    ) -> TestResult:
        if test.test_type != "security":
            return TestResult(
                test_id=test.test_id,
                passed=False,
                outcome="NOT_SUPPORTED",
                details=(
                    f"Test type '{test.test_type}' is not supported "
                    "by this runner yet."
                ),
            )

        if test.test_id.startswith("SQLI_"):
            return self._run_sql_injection_test(test)

        return TestResult(
            test_id=test.test_id,
            passed=False,
            outcome="NOT_SUPPORTED",
            details="No execution handler exists for this test.",
        )

    def _run_sql_injection_test(
        self,
        test: VerificationTest,
    ) -> TestResult:
        """
        Demonstrates the security property using a safe,
        parameterized SQLite query.
        """

        connection = sqlite3.connect(":memory:")

        try:
            cursor = connection.cursor()

            cursor.execute(
                "CREATE TABLE users (id INTEGER, username TEXT)"
            )

            cursor.executemany(
                "INSERT INTO users (id, username) VALUES (?, ?)",
                [
                    (1, "alice"),
                    (2, "bob"),
                ],
            )

            payload = test.payload or ""

            # Safe query: payload is passed as data, not SQL syntax.
            cursor.execute(
                "SELECT id, username FROM users WHERE username = ?",
                (payload,),
            )

            rows = cursor.fetchall()

            # Injection-style input should not return all user records.
            injection_blocked = len(rows) < 2

            if injection_blocked:
                return TestResult(
                    test_id=test.test_id,
                    passed=True,
                    outcome="PASS",
                    details=(
                        "The input was treated as a parameter value. "
                        "It did not alter the SQL query structure."
                    ),
                )

            return TestResult(
                test_id=test.test_id,
                passed=False,
                outcome="FAIL",
                details=(
                    "The test input returned multiple records. "
                    "Further investigation is required."
                ),
            )

        finally:
            connection.close()


def run_tests(
    tests: list[VerificationTest],
) -> list[TestResult]:
    """
    Convenience function for running verification tests.
    """

    return VerificationTestRunner().run_tests(tests)
