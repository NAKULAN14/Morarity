"""
Comprehensive Verification Integrity Regression Tests.
Covers all 18 cases required by Master Correction Issue 6.
"""

import sqlite3

from app.agent.agent_loop import MoriartyAgentLoop
from app.agent.planner import AgentPlanner
from app.execution.local_app_runner import LocalAppVerificationRunner
from app.execution.source_executor import (
    ControlledSourceExecutor,
    SourceBoundUserApp,
    check_source_equivalence,
)
from app.models.schemas import (
    Evidence,
    FunctionalityInvariant,
    TestResult,
    Verdict,
)
from app.scenarios.correct_patch import PatchedUserApp
from app.scenarios.incomplete_patch import IncompletePatchUserApp
from app.scenarios.vulnerable import VulnerableUserApp
from app.verification.verdict_engine import VerdictEngine


VULN_SOURCE = """def get_user_by_username(cursor, username: str):
    query = "SELECT id, username, role, email FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
"""

SAFE_SOURCE = """def get_user_by_username(cursor, username: str):
    cursor.execute(
        "SELECT id, username, role, email FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchall()
"""

INCOMPLETE_SOURCE = """def get_user_by_username(cursor, username: str):
    sanitized = username.replace("--", "")
    query = "SELECT id, username, role, email FROM users WHERE username = '" + sanitized + "'"
    cursor.execute(query)
    return cursor.fetchall()
"""


# =============================================================================
# 1-4: Source/Runtime Mismatch and Provenance Tests
# =============================================================================

def test_1_submitted_vulnerable_source_with_safe_fixture_never_verified(tmp_path):
    """
    Case 1: Submitted patched source is vulnerable, but separately supplied safe fixture is used.
    Must NOT return VERIFIED.
    """
    agent = MoriartyAgentLoop(max_tests=3)
    safe_app = PatchedUserApp()
    vuln_app = VulnerableUserApp()

    # Pass INCOMPLETE (vulnerable) source code as patched_source, but safe_app as patched_app
    result = agent.run(
        original_source=VULN_SOURCE,
        patched_source=INCOMPLETE_SOURCE,  # Vulnerable source!
        vulnerable_app=vuln_app,
        patched_app=safe_app,              # Separately supplied safe fixture!
        report_path=str(tmp_path / "case1.json"),
    )

    assert result.verdict != Verdict.VERIFIED
    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.source_runtime_match is False
    assert result.target_provenance == "PROVENANCE_MISMATCH"


def test_2_submitted_safe_source_with_unrelated_vulnerable_target_never_verified(tmp_path):
    """
    Case 2: Submitted patched source is safe, but unrelated vulnerable runtime target is supplied.
    Must NOT claim submitted source was dynamically verified.
    """
    agent = MoriartyAgentLoop(max_tests=3)
    vuln_app = VulnerableUserApp()
    unrelated_vuln_app = IncompletePatchUserApp()

    result = agent.run(
        original_source=VULN_SOURCE,
        patched_source=SAFE_SOURCE,            # Safe source!
        vulnerable_app=vuln_app,
        patched_app=unrelated_vuln_app,        # Unrelated vulnerable target!
        report_path=str(tmp_path / "case2.json"),
    )

    assert result.verdict != Verdict.VERIFIED
    assert result.source_runtime_match is False


def test_3_runtime_target_provenance_missing_is_inconclusive(tmp_path):
    """
    Case 3: Runtime target provenance is missing (untracked external class).
    Must return INCONCLUSIVE.
    """
    class UntrackedApp:
        def search_users(self, username):
            return []

    agent = MoriartyAgentLoop(max_tests=3)
    result = agent.run(
        original_source=VULN_SOURCE,
        patched_source=SAFE_SOURCE,
        vulnerable_app=UntrackedApp(),
        patched_app=UntrackedApp(),
        report_path=str(tmp_path / "case3.json"),
    )

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.source_runtime_match is False
    assert "provenance" in result.verdict_summary.lower()


def test_4_unsupported_source_structure_is_inconclusive():
    """
    Case 4: Unsupported source structure (e.g. dangerous imports, exec).
    Executor rejects and marks inconclusive.
    """
    dangerous_source = """
import os
def get_user_by_username(cursor, username: str):
    os.system("whoami")
    return []
"""
    app, message = ControlledSourceExecutor.create_app_from_source(dangerous_source)
    assert app is None
    assert "disallowed" in message.lower()


# =============================================================================
# 5-10: SQL Injection Result Semantics Tests
# =============================================================================

def test_5_payload_returning_one_unauthorized_record_fails():
    """
    Case 5: Payload returns exactly one unauthorized record.
    Must NOT pass simply because row count is 1.
    """
    class SingleUnauthorizedLeakApp:
        def search_users(self, username):
            # Leaks exactly 1 row (charlie), but queried username was an injection string!
            return [{"id": 3, "username": "charlie", "role": "admin", "email": "charlie@local"}]

    runner = LocalAppVerificationRunner(
        vulnerable_app=VulnerableUserApp(),
        patched_app=SingleUnauthorizedLeakApp(),
    )

    # Malicious injection payload
    result = runner.run_test(payload="charlie' --")
    # Even though len(patched_rows) == 1, row['username'] != payload!
    assert result.patch_blocks_payload is False
    assert result.passed is False
    assert result.outcome == "FAIL"


def test_6_payload_returning_zero_rows_requires_baseline_exploitability():
    """
    Case 6: Payload returns zero rows on patched target, but baseline is NOT exploitable.
    Must NOT pass as differential verification.
    """
    class InertBaselineApp:
        def search_users(self, username):
            # Baseline is inert; does not alter query and returns 0 rows
            return []

    runner = LocalAppVerificationRunner(
        vulnerable_app=InertBaselineApp(),
        patched_app=PatchedUserApp(),
    )

    result = runner.run_test(payload="non_exploitative_probe")
    assert result.baseline_exploitable is False
    assert result.passed is False
    assert "inconclusive" in result.details.lower()


def test_7_parameterized_query_legitimately_returning_record_not_rejected():
    """
    Case 7: Parameterized query legitimately returns a matching record (literal username).
    Must NOT be rejected solely because a row was returned.
    """
    runner = LocalAppVerificationRunner(
        vulnerable_app=VulnerableUserApp(),
        patched_app=PatchedUserApp(),
    )

    # Legitimate search for bob
    result = runner.run_test(payload="bob")
    # All returned rows match payload ("bob"), so no unauthorized records leaked
    assert result.patch_blocks_payload is True


def test_8_incomplete_sanitization_patch_produces_rejected():
    """
    Case 8: Incomplete sanitization patch (replaces '--' but leaves quotes).
    Must produce REJECTED when runtime evidence demonstrates exploitability.
    """
    runner = LocalAppVerificationRunner(
        vulnerable_app=VulnerableUserApp(),
        patched_app=IncompletePatchUserApp(),
    )

    result = runner.run_test(payload="' OR '1'='1")
    assert result.baseline_exploitable is True
    assert result.patch_blocks_payload is False
    assert result.passed is False
    assert result.outcome == "FAIL"


def test_9_benign_functionality_test_failure_not_verified():
    """
    Case 9: Benign functionality test fails.
    Must NOT produce VERIFIED.
    """
    class BrokenFunctionalityApp:
        def search_users(self, username):
            # Safe from injection, but breaks all lookups (returns empty)
            return []

    runner = LocalAppVerificationRunner(
        vulnerable_app=VulnerableUserApp(),
        patched_app=BrokenFunctionalityApp(),
    )

    result = runner.run_test(payload="' OR '1'='1")
    assert result.functionality_intact is False
    assert result.passed is False


def test_10_runner_exception_produces_inconclusive():
    """
    Case 10: Runner throws an exception during execution.
    Must produce INCONCLUSIVE.
    """
    class CrashingApp:
        def search_users(self, username):
            raise sqlite3.OperationalError("Database disk image is malformed")

    runner = LocalAppVerificationRunner(
        vulnerable_app=CrashingApp(),
        patched_app=PatchedUserApp(),
    )

    result = runner.run_test(payload="' OR '1'='1")
    assert result.outcome == "ERROR"
    assert result.error is not None

    engine = VerdictEngine()
    test_res = result.to_test_result()
    ev = Evidence(
        evidence_id="err",
        test_id=test_res.test_id,
        category="REAL_APPLICATION_VERIFICATION",
        description=test_res.details,
        observed={"outcome": "ERROR", "error": test_res.error},
        supports_verification=False,
    )
    verdict, summary = engine.decide([ev])
    assert verdict == Verdict.INCONCLUSIVE


# =============================================================================
# 11-18: Verdict Consistency and Integrity Tests
# =============================================================================

def test_11_budget_exhaustion_before_sufficient_evidence_is_inconclusive():
    """
    Case 11: Budget exhausted before sufficient evidence.
    Action is STOP_INCONCLUSIVE, stopping reason is explicit.
    """
    planner = AgentPlanner(max_tests=1)
    fake_fixture_result = TestResult(
        test_id="SIM_001",
        passed=True,
        outcome="PASS",
        details="Fixture passed",
    )
    decision = planner.plan([fake_fixture_result])
    assert decision.action == "STOP_INCONCLUSIVE"
    assert decision.stopping_reason == "TEST_BUDGET_EXHAUSTED_WITHOUT_SUFFICIENT_EVIDENCE"


def test_12_budget_exhaustion_after_sufficient_evidence_is_consistent_and_verified(tmp_path):
    """
    Case 12: Budget exhaustion after sufficient evidence.
    Verdict and stopping reason must be explicit and consistent (STOP_VERIFIED).
    """
    vuln_app = VulnerableUserApp()
    patch_app = PatchedUserApp()
    agent = MoriartyAgentLoop(max_tests=2)

    result = agent.run(
        original_source=vuln_app.source_code,
        patched_source=patch_app.source_code,
        vulnerable_app=vuln_app,
        patched_app=patch_app,
        report_path=str(tmp_path / "case12.json"),
    )

    assert result.verdict == Verdict.VERIFIED
    assert result.final_action == "STOP_VERIFIED"
    assert result.stopping_reason == "VERIFICATION_REQUIREMENTS_SATISFIED"


def test_13_controlled_demonstration_only_never_verified(tmp_path):
    """
    Case 13: Controlled demonstration only.
    Must NEVER produce VERIFIED.
    """
    agent = MoriartyAgentLoop(max_tests=2)
    result = agent.run(
        original_source=VULN_SOURCE,
        patched_source=SAFE_SOURCE,
        vulnerable_app=None,
        patched_app=None,
        report_path=str(tmp_path / "case13.json"),
    )

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.final_action == "STOP_INCONCLUSIVE"


def test_14_static_analysis_only_never_verified():
    """
    Case 14: Static analysis only.
    Must NEVER produce VERIFIED.
    """
    engine = VerdictEngine()
    static_ev = Evidence(
        evidence_id="stat-1",
        test_id="STATIC_PATCH_COMPARISON",
        category="STATIC_ANALYSIS",
        description="Static improvement detected",
        observed={"status": "PATCH_PATTERN_IMPROVED", "static_improvement_detected": True},
        supports_verification=False,
    )
    verdict, summary = engine.decide([static_ev])
    assert verdict == Verdict.INCONCLUSIVE
    assert verdict != Verdict.VERIFIED


def test_15_contradictory_evidence_not_verified():
    """
    Case 15: Contradictory evidence (one test passes, but another demonstrates exploitability).
    Must NOT return VERIFIED.
    """
    engine = VerdictEngine()
    pass_ev = Evidence(
        evidence_id="e1",
        test_id="T1",
        category="REAL_APPLICATION_VERIFICATION",
        description="Passed test",
        observed={
            "outcome": "PASS", "passed": True, "baseline_exploitable": True,
            "patch_blocks_payload": True, "functionality_intact": True, "source_runtime_match": True
        },
        supports_verification=True,
    )
    fail_ev = Evidence(
        evidence_id="e2",
        test_id="T2",
        category="REAL_APPLICATION_VERIFICATION",
        description="Failed test (exploit succeeded)",
        observed={
            "outcome": "FAIL", "passed": False, "baseline_exploitable": True,
            "patch_blocks_payload": False, "functionality_intact": True, "source_runtime_match": True
        },
        supports_verification=False,
    )

    verdict, summary = engine.decide([pass_ev, fail_ev])
    assert verdict == Verdict.REJECTED
    assert verdict != Verdict.VERIFIED


def test_16_forged_supports_verification_evidence_rejected():
    """
    Case 16: Manually forged supports_verification=True evidence without required runtime fields.
    Must NOT produce VERIFIED.
    """
    engine = VerdictEngine()
    forged_ev = Evidence(
        evidence_id="forged",
        test_id="FORGED_001",
        category="REAL_APPLICATION_VERIFICATION",
        description="Fake passing evidence",
        observed={
            # Missing baseline_exploitable, patch_blocks_payload, functionality_intact, source_runtime_match
            "outcome": "PASS",
            "passed": True,
        },
        supports_verification=True,  # Forged label!
    )

    verdict, summary = engine.decide([forged_ev])
    assert verdict == Verdict.INCONCLUSIVE
    assert verdict != Verdict.VERIFIED


def test_17_unsupported_source_syntax_inconclusive(tmp_path):
    """
    Case 17: Unsupported source syntax error.
    Must return INCONCLUSIVE.
    """
    agent = MoriartyAgentLoop(max_tests=2)
    result = agent.run(
        original_source=VULN_SOURCE,
        patched_source="def invalid_syntax(:",
        report_path=str(tmp_path / "case17.json"),
    )
    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.final_action == "STOP_INCONCLUSIVE"


def test_18_existing_successful_verified_scenario_verified_with_scope(tmp_path):
    """
    Case 18: Existing successful verified scenario.
    Must return VERIFIED within its explicitly stated scope.
    """
    vuln_app = VulnerableUserApp()
    patch_app = PatchedUserApp()
    agent = MoriartyAgentLoop(max_tests=3)

    result = agent.run(
        original_source=vuln_app.source_code,
        patched_source=patch_app.source_code,
        vulnerable_app=vuln_app,
        patched_app=patch_app,
        report_path=str(tmp_path / "case18.json"),
    )

    assert result.verdict == Verdict.VERIFIED
    assert result.final_action == "STOP_VERIFIED"
    assert "Verification scope:" in result.verdict_summary
    assert "targeted local sqlite" in result.verdict_summary.lower()


# =============================================================================
# 19-27: Source-Code Review Regression Tests
# =============================================================================

def test_19_patch_blocking_injection_but_breaking_functionality_produces_inconclusive(tmp_path):
    """
    Finding 1 & 4: A patch that blocks SQL injection but breaks benign functionality -> INCONCLUSIVE.
    Must NOT produce VERIFIED or REJECTED.
    """
    class BrokenBenignApp:
        SOURCE_CODE = SAFE_SOURCE

        def search_users(self, username):
            # Blocks injection by returning empty, but breaks benign lookups as well
            return []

    agent = MoriartyAgentLoop(max_tests=2)
    vuln_app = VulnerableUserApp()
    broken_app = BrokenBenignApp()

    result = agent.run(
        original_source=vuln_app.source_code,
        patched_source=broken_app.SOURCE_CODE,
        vulnerable_app=vuln_app,
        patched_app=broken_app,
        report_path=str(tmp_path / "case19.json"),
    )

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.verdict != Verdict.VERIFIED
    assert result.verdict != Verdict.REJECTED
    assert "functionality" in result.verdict_summary.lower()


def test_20_mismatched_runtime_target_demonstrating_exploitability_produces_inconclusive(tmp_path):
    """
    Finding 1 & 4: A mismatched runtime target demonstrating exploitability -> INCONCLUSIVE for submitted patch.
    Must NOT produce REJECTED for the submitted patch.
    """
    agent = MoriartyAgentLoop(max_tests=2)
    vuln_app = VulnerableUserApp()
    # unrelated vulnerable app that leaks records
    unrelated_app = IncompletePatchUserApp()

    result = agent.run(
        original_source=vuln_app.source_code,
        patched_source=SAFE_SOURCE,  # submitted patch is SAFE!
        vulnerable_app=vuln_app,
        patched_app=unrelated_app,   # mismatched target that leaks records!
        report_path=str(tmp_path / "case20.json"),
    )

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.verdict != Verdict.REJECTED
    assert result.verdict != Verdict.VERIFIED
    assert result.source_runtime_match is False
    assert "provenance" in result.verdict_summary.lower()


def test_21_source_strings_differing_in_whitespace_inside_sql_literals_provenance_mismatch():
    """
    Finding 2 & 4: Source strings differing only in whitespace inside SQL literals -> provenance mismatch.
    """
    src1 = """def get_user_by_username(cursor, username: str):
    cursor.execute(
        "SELECT  id, username, role, email FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchall()
"""
    src2 = """def get_user_by_username(cursor, username: str):
    cursor.execute(
        "SELECT id, username, role, email FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchall()
"""
    # They differ in whitespace inside "SELECT  id" vs "SELECT id"
    assert check_source_equivalence(src1, src2) is False


def test_22_source_strings_with_hash_inside_string_literals_no_incorrect_provenance_match():
    """
    Finding 2 & 4: Source strings containing '#' inside string literals -> no incorrect provenance match.
    """
    src_with_hash = """def get_user_by_username(cursor, username: str):
    cursor.execute(
        "SELECT id FROM users WHERE tag = '#admin' AND username = ?",
        (username,),
    )
    return cursor.fetchall()
"""
    src_without_hash = """def get_user_by_username(cursor, username: str):
    cursor.execute(
        "SELECT id FROM users WHERE tag = 'admin' AND username = ?",
        (username,),
    )
    return cursor.fetchall()
"""
    # AST comparison must not strip '#admin' and confuse it with 'admin'
    assert check_source_equivalence(src_with_hash, src_without_hash) is False

    # Exterior comment outside strings must still be ignored
    src_with_exterior_comment = """def get_user_by_username(cursor, username: str):
    # This is a real Python comment
    cursor.execute(
        "SELECT id FROM users WHERE tag = '#admin' AND username = ?",
        (username,),
    )
    return cursor.fetchall()
"""
    assert check_source_equivalence(src_with_hash, src_with_exterior_comment) is True


def test_23_missing_submitted_source_executed_never_verified():
    """
    Finding 3 & 4: Missing submitted_source_executed -> never VERIFIED.
    """
    engine = VerdictEngine()
    ev = Evidence(
        evidence_id="ev23",
        test_id="SQLI_REAL_001",
        category="REAL_APPLICATION_VERIFICATION",
        description="Dynamic test",
        observed={
            "outcome": "PASS",
            "passed": True,
            "baseline_exploitable": True,
            "patch_blocks_payload": True,
            "functionality_intact": True,
            "source_runtime_match": True,
            "target_type": "REAL_LOCAL_APPLICATION",
            "target_provenance": "RESTRICTED_SOURCE_ENV",
            "verification_scope": "Targeted local SQLite query construction path",
            # missing submitted_source_executed
            "submitted_source_executed": False,
        },
        supports_verification=True,
    )
    verdict, summary = engine.decide([ev])
    assert verdict == Verdict.INCONCLUSIVE
    assert verdict != Verdict.VERIFIED


def test_24_missing_or_invalid_target_provenance_never_verified():
    """
    Finding 3 & 4: Missing or invalid target provenance -> never VERIFIED.
    """
    engine = VerdictEngine()
    ev_invalid_prov = Evidence(
        evidence_id="ev24",
        test_id="SQLI_REAL_001",
        category="REAL_APPLICATION_VERIFICATION",
        description="Dynamic test with invalid provenance",
        observed={
            "outcome": "PASS",
            "passed": True,
            "baseline_exploitable": True,
            "patch_blocks_payload": True,
            "functionality_intact": True,
            "source_runtime_match": True,
            "submitted_source_executed": True,
            "target_type": "REAL_LOCAL_APPLICATION",
            "target_provenance": "UNTRUSTED_OR_UNKNOWN_ORIGIN",  # Not in allowed provenances!
            "verification_scope": "Targeted local SQLite query construction path",
        },
        supports_verification=True,
    )
    verdict, summary = engine.decide([ev_invalid_prov])
    assert verdict == Verdict.INCONCLUSIVE
    assert verdict != Verdict.VERIFIED


def test_25_existing_valid_parameterized_patch_still_verified(tmp_path):
    """
    Finding 4: Existing valid parameterized patch -> still VERIFIED.
    """
    vuln_app = VulnerableUserApp()
    patch_app = PatchedUserApp()
    agent = MoriartyAgentLoop(max_tests=3)

    result = agent.run(
        original_source=vuln_app.source_code,
        patched_source=patch_app.source_code,
        vulnerable_app=vuln_app,
        patched_app=patch_app,
        report_path=str(tmp_path / "case25.json"),
    )

    assert result.verdict == Verdict.VERIFIED
    assert result.final_action == "STOP_VERIFIED"
    assert "Verification scope:" in result.verdict_summary


def test_26_existing_incomplete_patch_still_rejected(tmp_path):
    """
    Finding 4: Existing incomplete patch -> still REJECTED.
    """
    vuln_app = VulnerableUserApp()
    incomplete_app = IncompletePatchUserApp()
    agent = MoriartyAgentLoop(max_tests=3)

    result = agent.run(
        original_source=vuln_app.source_code,
        patched_source=incomplete_app.source_code,
        vulnerable_app=vuln_app,
        patched_app=incomplete_app,
        report_path=str(tmp_path / "case26.json"),
    )

    assert result.verdict == Verdict.REJECTED
    assert result.final_action == "STOP_REJECTED"
    assert "remains exploitable" in result.verdict_summary


def test_27_runtime_error_without_exploit_evidence_is_inconclusive():
    """
    Finding 1 & 4: Runtime errors without exploit evidence -> INCONCLUSIVE.
    """
    engine = VerdictEngine()
    error_ev = Evidence(
        evidence_id="ev27",
        test_id="SQLI_REAL_001",
        category="REAL_APPLICATION_VERIFICATION",
        description="Database connection error",
        observed={
            "outcome": "ERROR",
            "error": "sqlite3.OperationalError: disk I/O error",
            "source_runtime_match": True,
        },
        supports_verification=False,
    )

    verdict, summary = engine.decide([error_ev])
    assert verdict == Verdict.INCONCLUSIVE
    assert "errors" in summary.lower()
