
import sqlite3
from dataclasses import dataclass

from app.models.schemas import TestResult


@dataclass
class DifferentialTestResult:
    payload: str
    vulnerable_rows: list[tuple]
    patched_rows: list[tuple]
    baseline_exploitable: bool
    patch_blocks_payload: bool
    passed: bool
    details: str
    error: str | None = None


class DifferentialSQLRunner:
    """
    Controlled SQLite differential test.

    Compares a deliberately vulnerable query implementation
    against a parameterized implementation.

    This is a demonstration fixture. It does not execute
    arbitrary submitted source code.
    """

    def _create_database(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")

        connection.execute(
            "CREATE TABLE users (id INTEGER, username TEXT)"
        )

        connection.executemany(
            "INSERT INTO users (id, username) VALUES (?, ?)",
            [
                (1, "alice"),
                (2, "bob"),
            ],
        )

        return connection

    def _run_vulnerable_query(
        self,
        payload: str,
    ) -> list[tuple]:
        connection = self._create_database()

        try:
            # Deliberately unsafe: input is concatenated into SQL.
            query = (
                "SELECT id, username FROM users "
                f"WHERE username = '{payload}'"
            )

            cursor = connection.execute(query)
            return cursor.fetchall()

        finally:
            connection.close()

    def _run_patched_query(
        self,
        payload: str,
    ) -> list[tuple]:
        connection = self._create_database()

        try:
            # Safe: input is supplied separately as a parameter.
            cursor = connection.execute(
                "SELECT id, username FROM users WHERE username = ?",
                (payload,),
            )

            return cursor.fetchall()

        finally:
            connection.close()

    def run(
        self,
        payload: str = "' OR '1'='1",
    ) -> DifferentialTestResult:

        try:
            vulnerable_rows = self._run_vulnerable_query(payload)
            patched_rows = self._run_patched_query(payload)

        except sqlite3.Error as exc:
            return DifferentialTestResult(
                payload=payload,
                vulnerable_rows=[],
                patched_rows=[],
                baseline_exploitable=False,
                patch_blocks_payload=False,
                passed=False,
                details=(
                    "The SQL test could not complete because "
                    "the demonstration query produced an error."
                ),
                error=str(exc),
            )

        baseline_exploitable = len(vulnerable_rows) > 1
        patch_blocks_payload = len(patched_rows) <= 1

        passed = (
            baseline_exploitable
            and patch_blocks_payload
        )

        if passed:
            details = (
                "The baseline was vulnerable to the test payload, "
                "while the parameterized demonstration blocked it."
            )
        else:
            details = (
                "The expected vulnerable-versus-patched behavior "
                "was not observed."
            )

        return DifferentialTestResult(
            payload=payload,
            vulnerable_rows=vulnerable_rows,
            patched_rows=patched_rows,
            baseline_exploitable=baseline_exploitable,
            patch_blocks_payload=patch_blocks_payload,
            passed=passed,
            details=details,
        )

    def run_as_test_result(
        self,
        payload: str = "' OR '1'='1",
    ) -> TestResult:

        result = self.run(payload)

        if result.error:
            outcome = "ERROR"
        elif result.passed:
            outcome = "PASS"
        else:
            outcome = "FAIL"

        return TestResult(
            test_id="SQLI_DIFFERENTIAL_001",
            passed=result.passed,
            outcome=outcome,
            details=(
                f"{result.details} "
                f"Vulnerable rows: {len(result.vulnerable_rows)}. "
                f"Patched rows: {len(result.patched_rows)}."
            ),
            error=result.error,
        )
