"""
Local Application Verification Runner.
Executes controlled dynamic security tests against real local Python/SQLite applications
or submitted-source runtime environments, enforcing strict security and functionality properties.
"""

import time
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Optional

from app.models.schemas import FunctionalityInvariant, TestResult


@dataclass
class LocalAppTestResult:
    """
    Detailed empirical observation from executing a dynamic verification test.
    Distinguished from simulated or controlled static demonstration fixtures.
    """
    test_id: str
    payload: str
    target_type: str = "REAL_LOCAL_APPLICATION"
    target_provenance: str = "RESTRICTED_SOURCE_ENV"
    submitted_source_executed: bool = True
    source_runtime_match: bool = True
    vulnerable_rows: list[dict[str, Any]] = field(default_factory=list)
    patched_rows: list[dict[str, Any]] = field(default_factory=list)
    functionality_check_rows: list[dict[str, Any]] = field(default_factory=list)
    baseline_exploitable: bool = False
    patch_blocks_payload: bool = False
    functionality_intact: bool = False
    passed: bool = False
    outcome: str = "FAIL"
    expected_behavior: str = ""
    observed_behavior: str = ""
    details: str = ""
    execution_time_ms: float = 0.0
    error: Optional[str] = None
    verification_scope: str = "Targeted local SQLite user search query path"

    def to_test_result(self) -> TestResult:
        return TestResult(
            test_id=self.test_id,
            passed=self.passed,
            outcome=self.outcome,
            details=self.details,
            execution_time_ms=self.execution_time_ms,
            error=self.error,
            expected_behavior=self.expected_behavior,
            observed_behavior=self.observed_behavior,
            baseline_exploitable=self.baseline_exploitable,
            patch_blocks_payload=self.patch_blocks_payload,
            functionality_intact=self.functionality_intact,
        )


class LocalAppVerificationRunner:
    """
    Verifies SQL injection patches by executing controlled payloads against
    vulnerable baseline and patched local targets.

    Evaluates:
    1. Baseline exploitability (payload alters SQL syntax on vulnerable baseline).
    2. Patch neutralization (payload is strictly treated as parameter data; no unauthorized rows).
    3. Functionality preservation (benign functionality invariant remains intact).
    """

    def __init__(
        self,
        vulnerable_app: Any,
        patched_app: Any,
        functionality_invariant: Optional[FunctionalityInvariant] = None,
        require_functionality_invariant: bool = True,
        target_type: str = "REAL_LOCAL_APPLICATION",
        target_provenance: str = "RESTRICTED_SOURCE_ENV",
        submitted_source_executed: bool = True,
        source_runtime_match: bool = True,
    ) -> None:
        self.vulnerable_app = vulnerable_app
        self.patched_app = patched_app
        self.require_functionality_invariant = require_functionality_invariant

        # Allow caller to provide a custom invariant, or default to the fixture invariant
        if functionality_invariant is not None:
            self.functionality_invariant: Optional[FunctionalityInvariant] = functionality_invariant
        elif require_functionality_invariant:
            self.functionality_invariant = FunctionalityInvariant.default_fixture_invariant()
        else:
            self.functionality_invariant = None

        self.target_type = target_type
        self.target_provenance = target_provenance
        self.submitted_source_executed = submitted_source_executed
        self.source_runtime_match = source_runtime_match

    def run_test(
        self,
        payload: str,
        test_id: str = "SQLI_REAL_001",
    ) -> LocalAppTestResult:
        """
        Execute payload against both vulnerable and patched local applications,
        capturing actual observations, error states, and execution metrics.
        """
        start_time = time.perf_counter()

        expected = (
            "Baseline application should be vulnerable (payload alters query logic to return unauthorized records); "
            "patched application must treat payload strictly as literal parameter data (only exact literal match or 0 records); "
            "configured application functionality invariants must remain intact."
        )

        try:
            # 1. Execute against vulnerable baseline
            vuln_rows = self.vulnerable_app.search_users(payload)

            # 2. Execute against patched implementation
            patched_rows = self.patched_app.search_users(payload)

            # 3. Check functionality invariant
            func_rows: list[dict[str, Any]] = []
            functionality_intact = False
            func_msg = ""

            if self.functionality_invariant is not None:
                invariant = self.functionality_invariant
                func_rows = self.patched_app.search_users(invariant.input_value)
                matches = [
                    r for r in func_rows
                    if r.get(invariant.expected_field) == invariant.expected_value
                ]
                if len(func_rows) == invariant.expected_count and len(matches) == invariant.expected_count:
                    functionality_intact = True
                    func_msg = f"Functionality invariant '{invariant.name}' satisfied ({len(matches)} match)."
                else:
                    functionality_intact = False
                    func_msg = (
                        f"Functionality invariant '{invariant.name}' FAILED. "
                        f"Expected {invariant.expected_count} records matching {invariant.expected_field}='{invariant.expected_value}', "
                        f"observed {len(func_rows)} records."
                    )
            elif self.require_functionality_invariant:
                functionality_intact = False
                func_msg = "Required functionality invariant was not provided."
            else:
                # Invariant not required for this specific probe
                functionality_intact = True
                func_msg = "Functionality invariant was not required for this test."

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

            # 4. Rigorous SQL Injection Semantic Evaluation
            # Baseline is exploitable if SQL injection altered query syntax to return records
            # that do NOT literally match the queried username
            unauthorized_vuln_rows = [
                r for r in vuln_rows
                if r.get("username") != payload
            ]
            baseline_exploitable = len(unauthorized_vuln_rows) > 0 or len(vuln_rows) > 1

            # Patch successfully blocks payload if NO unauthorized records are returned.
            # In a parameterized query `WHERE username = ?`, only a record whose username literally
            # equals the payload can be returned. If any returned record has username != payload,
            # then query syntax was altered or sanitization bypassed!
            unauthorized_patched_rows = [
                r for r in patched_rows
                if r.get("username") != payload
            ]
            patch_blocks_payload = (len(unauthorized_patched_rows) == 0)

            # Overall test pass condition:
            # - Baseline must be proven exploitable for this payload (not a no-op payload)
            # - Patch must block the payload (no unauthorized records)
            # - Functionality must remain intact
            passed = (
                baseline_exploitable
                and patch_blocks_payload
                and functionality_intact
            )
            outcome = "PASS" if passed else "FAIL"

            observed = (
                f"Vulnerable baseline returned {len(vuln_rows)} records "
                f"({len(unauthorized_vuln_rows)} unauthorized; baseline_exploitable={baseline_exploitable}). "
                f"Patched target returned {len(patched_rows)} records "
                f"({len(unauthorized_patched_rows)} unauthorized; patch_blocks_payload={patch_blocks_payload}). "
                f"{func_msg}"
            )

            if passed:
                details = (
                    f"Differential runtime test succeeded. "
                    f"Payload demonstrated baseline exploitability on vulnerable target ({len(vuln_rows)} rows) "
                    f"and was strictly treated as literal parameter on patched target (0 unauthorized rows). "
                    f"{func_msg}"
                )
            elif not baseline_exploitable:
                details = (
                    "Test inconclusive: baseline application did not exhibit exploitability for this payload. "
                    "Cannot establish differential security."
                )
            elif not patch_blocks_payload:
                details = (
                    f"Verification REJECTED: Patched application leaked {len(unauthorized_patched_rows)} "
                    f"unauthorized records for payload '{payload}'. Vulnerability remains exploitable."
                )
            else:
                details = f"Verification failed: {func_msg}"

            return LocalAppTestResult(
                test_id=test_id,
                payload=payload,
                target_type=self.target_type,
                target_provenance=self.target_provenance,
                submitted_source_executed=self.submitted_source_executed,
                source_runtime_match=self.source_runtime_match,
                vulnerable_rows=vuln_rows,
                patched_rows=patched_rows,
                functionality_check_rows=func_rows,
                baseline_exploitable=baseline_exploitable,
                patch_blocks_payload=patch_blocks_payload,
                functionality_intact=functionality_intact,
                passed=passed,
                outcome=outcome,
                expected_behavior=expected,
                observed_behavior=observed,
                details=details,
                execution_time_ms=elapsed_ms,
                error=None,
            )

        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return LocalAppTestResult(
                test_id=test_id,
                payload=payload,
                target_type=self.target_type,
                target_provenance=self.target_provenance,
                submitted_source_executed=self.submitted_source_executed,
                source_runtime_match=self.source_runtime_match,
                baseline_exploitable=False,
                patch_blocks_payload=False,
                functionality_intact=False,
                passed=False,
                outcome="ERROR",
                expected_behavior=expected,
                observed_behavior=f"Execution raised exception: {exc}",
                details=f"Local application test execution encountered an error: {exc}",
                execution_time_ms=elapsed_ms,
                error=str(exc),
            )
