"""
Tests for Moriarty's Adaptive SQL Injection Verification Framework.

Validates:
1. Structured test catalog (12 categories, 40 tests, SQLite driver execution constraints).
2. Adaptive test planning progression (PLAN -> EXECUTE -> OBSERVE -> ADAPT -> VERIFY).
3. Payload deduplication preventing repeated tests.
4. Configurable budget enforcement (Quick: 5, Standard: 15, Thorough: 30, Custom).
5. Accurate coverage tracking (available, executed, passed, failed, not applicable, invariants).
6. Invariant violation producing STOP_REJECTED / REJECTED.
7. Budget exhaustion with remaining gaps producing INCONCLUSIVE.
8. End-to-end adaptive loop execution with coverage metadata.
"""

from typing import Any
from unittest.mock import MagicMock

from app.agent.agent_loop import MoriartyAgentLoop
from app.agent.planner import AgentPlanner, PlanDecision
from app.api.routes import get_catalog_endpoint
from app.catalog.sql_catalog import (
    SQL_INJECTION_CATALOG,
    SQLInjectionCategory,
    SQLInjectionTestCase,
    get_catalog,
    get_categories,
    get_executable_tests,
    get_test_by_id,
    get_tests_by_category,
)
from app.execution.differential_runner import DifferentialTestResult
from app.execution.local_app_runner import LocalAppTestResult
from app.scenarios.correct_patch import PatchedUserApp
from app.scenarios.incomplete_patch import IncompletePatchUserApp
from app.scenarios.vulnerable import VulnerableUserApp


# -----------------------------------------------------------------------------
# 7. Catalog API Endpoint
# -----------------------------------------------------------------------------

def test_api_catalog_endpoint():
    """Verify get_catalog_endpoint returns categories and tests schema."""
    resp = get_catalog_endpoint()

    assert len(resp.categories) == 12
    assert len(resp.tests) == 40
    assert resp.total_tests == 40
    assert resp.executable_tests == 37
    assert resp.unsupported_tests == 3

    # Ensure stacked queries marked correctly in API response
    stacked = [t for t in resp.tests if t.category == SQLInjectionCategory.STACKED_QUERIES.value]
    assert len(stacked) == 3
    for s in stacked:
        assert s.execution_support == "UNSUPPORTED_IN_DRIVER_API"

def test_catalog_structure_and_categories():
    """Verify that catalog includes all 12 categories, 40 tests, and correct metadata."""
    catalog = get_catalog()
    assert len(catalog) == 40, f"Expected 40 catalog tests, got {len(catalog)}"

    categories = get_categories()
    assert len(categories) == 12, f"Expected 12 categories, got {len(categories)}"

    # Check that all 12 enum categories are present in get_categories()
    enum_categories = {c.value for c in SQLInjectionCategory}
    retrieved_categories = {c["name"] for c in categories}
    assert enum_categories == retrieved_categories

    # Verify that every test case has all required fields populated
    for tc in catalog:
        assert tc.test_id, "Missing test_id"
        assert tc.name, "Missing name"
        assert tc.category in enum_categories, f"Invalid category: {tc.category}"
        assert tc.security_invariant, "Missing security_invariant"
        assert tc.payload, "Missing payload"
        assert tc.expected_behavior, "Missing expected_behavior"
        assert tc.execution_support in {"SUPPORTED", "UNSUPPORTED_IN_DRIVER_API"}
        assert tc.verification_weight in {"CRITICAL", "HIGH", "MEDIUM"}


def test_catalog_sqlite_execution_constraints():
    """Verify driver support tagging: 37 executable, 3 stacked queries unsupported."""
    executable = get_executable_tests()
    assert len(executable) == 37, f"Expected 37 executable tests, got {len(executable)}"

    # Stacked queries are unsupported in standard Python sqlite3 cursor.execute()
    stacked_tests = get_tests_by_category(SQLInjectionCategory.STACKED_QUERIES.value)
    assert len(stacked_tests) == 3
    for tc in stacked_tests:
        assert tc.execution_support == "UNSUPPORTED_IN_DRIVER_API"
        assert tc not in executable

    # Verify helper get_test_by_id
    t1 = get_test_by_id("SQLI_QUOTE_001")
    assert t1 is not None
    assert t1.test_id == "SQLI_QUOTE_001"
    assert t1.execution_support == "SUPPORTED"


# -----------------------------------------------------------------------------
# 2. Adaptive Planner Progression and Reasoning
# -----------------------------------------------------------------------------

def test_adaptive_planner_starts_with_quote_delimiter():
    """First planning step without prior results initiates quote/delimiter challenge."""
    planner = AgentPlanner(max_tests=5)
    decision = planner.plan(results=[])

    assert decision.action == "RUN_TEST"
    assert decision.next_payload is not None
    assert "No tests have been executed yet" in decision.reason
    assert decision.test_case is not None


def test_adaptive_planner_articulates_dynamic_reasoning():
    """Planner explains why subsequent tests are chosen based on prior observations."""
    planner = AgentPlanner(max_tests=10)

    # First test: quote delimiter
    d1 = planner.plan(results=[])
    assert d1.action == "RUN_TEST"

    # Simulate passing quote delimiter test
    r1 = LocalAppTestResult(
        test_id="SQLI_QUOTE_001",
        payload=d1.next_payload,
        target_type="REAL_LOCAL_APPLICATION",
        target_provenance="LOCAL_SQLITE_INSTANCE",
        submitted_source_executed=True,
        source_runtime_match=True,
        vulnerable_rows=[{"username": "admin"}],
        patched_rows=[],
        functionality_check_rows=[{"username": "alice"}],
        baseline_exploitable=True,
        patch_blocks_payload=True,
        functionality_intact=True,
        passed=True,
        outcome="PASS",
        observed_behavior="Blocked",
        expected_behavior="Blocked",
        category=SQLInjectionCategory.QUOTE_DELIMITER.value,
        security_invariant="UNTRUSTED_INPUT_CANNOT_ESCAPE_STRING_DELIMITER",
    )

    d2 = planner.plan(results=[r1])
    assert d2.action == "RUN_TEST"
    assert d2.next_payload != d1.next_payload


def test_deduplication_prevents_repeated_payloads():
    """Planner never selects a payload that has already been tested."""
    planner = AgentPlanner(max_tests=15)
    simulated_results = []

    for i in range(8):
        decision = planner.plan(results=simulated_results)
        if decision.action != "RUN_TEST":
            break

        payload = decision.next_payload
        # Ensure payload has not been seen
        prior_payloads = [r.payload for r in simulated_results]
        assert payload not in prior_payloads, f"Duplicate payload generated: {payload}"

        res = LocalAppTestResult(
            test_id=f"TEST_{i:03d}",
            payload=payload,
            target_type="REAL_LOCAL_APPLICATION",
            target_provenance="LOCAL_SQLITE_INSTANCE",
            submitted_source_executed=True,
            source_runtime_match=True,
            vulnerable_rows=[{"username": "vuln_record"}],
            patched_rows=[],
            functionality_check_rows=[{"username": "alice"}],
            baseline_exploitable=True,
            patch_blocks_payload=True,
            functionality_intact=True,
            passed=True,
            outcome="PASS",
            observed_behavior="Blocked",
            expected_behavior="Blocked",
            category=getattr(decision.test_case, "category", None),
            security_invariant=getattr(decision.test_case, "security_invariant", None),
        )
        simulated_results.append(res)

    assert len(simulated_results) >= 5
    unique_payloads = {r.payload for r in simulated_results}
    assert len(unique_payloads) == len(simulated_results)


# -----------------------------------------------------------------------------
# 3. Configurable Verification Budgets
# -----------------------------------------------------------------------------

def test_configurable_budgets_limit_execution():
    """Budgets (Quick=5, Standard=15, Thorough=30) strictly limit maximum planned tests."""
    for budget in [3, 5, 8]:
        planner = AgentPlanner(max_tests=budget)
        results = []
        for _ in range(budget + 2):
            decision = planner.plan(results=results)
            if decision.action != "RUN_TEST":
                break
            results.append(
                LocalAppTestResult(
                    test_id=f"TEST_{len(results)}",
                    payload=decision.next_payload,
                    target_type="REAL_LOCAL_APPLICATION",
                    target_provenance="LOCAL_SQLITE_INSTANCE",
                    submitted_source_executed=True,
                    source_runtime_match=True,
                    vulnerable_rows=[{"username": "admin"}],
                    patched_rows=[],
                    functionality_check_rows=[{"username": "alice"}],
                    baseline_exploitable=True,
                    patch_blocks_payload=True,
                    functionality_intact=True,
                    passed=True,
                    outcome="PASS",
                    observed_behavior="Blocked",
                    expected_behavior="Blocked",
                )
            )

        assert len(results) == budget
        final_decision = planner.plan(results=results)
        assert final_decision.action in {"STOP_VERIFIED", "STOP_INCONCLUSIVE"}


# -----------------------------------------------------------------------------
# 4. Invariant Violation (REJECTED) and Budget Exhaustion (INCONCLUSIVE)
# -----------------------------------------------------------------------------

def test_invariant_violation_stops_with_rejected():
    """When a patch fails to block an injection payload, planner halts immediately with STOP_REJECTED."""
    planner = AgentPlanner(max_tests=10)

    # Simulate a failed test where baseline was exploitable and patch leaked records
    r_fail = LocalAppTestResult(
        test_id="SQLI_REJECT_001",
        payload="' OR '1'='1",
        target_type="REAL_LOCAL_APPLICATION",
        target_provenance="LOCAL_SQLITE_INSTANCE",
        submitted_source_executed=True,
        source_runtime_match=True,
        vulnerable_rows=[{"username": "alice"}, {"username": "bob"}],
        patched_rows=[{"username": "alice"}, {"username": "bob"}],  # Leak!
        functionality_check_rows=[{"username": "alice"}],
        baseline_exploitable=True,
        patch_blocks_payload=False,  # Failed to block!
        functionality_intact=True,
        passed=False,
        outcome="FAIL",
        observed_behavior="Patched target leaked 2 records",
        expected_behavior="Blocked",
    )

    decision = planner.plan(results=[r_fail])
    assert decision.action == "STOP_REJECTED"
    assert "stopping verification because the vulnerability remains exploitable" in decision.reason


def test_budget_exhaustion_without_sufficient_evidence_stops_inconclusive():
    """Exhausting budget without sufficient real application tests stops with STOP_INCONCLUSIVE."""
    planner = AgentPlanner(max_tests=2)

    # 2 tests run against a CONTROLLED_FIXTURE (not REAL_LOCAL_APPLICATION)
    r1 = DifferentialTestResult(
        payload="' OR '1'='1",
        vulnerable_rows=[(1, "alice")],
        patched_rows=[],
        baseline_exploitable=True,
        patch_blocks_payload=True,
        passed=True,
        details="Controlled fixture execution",
    )
    r2 = DifferentialTestResult(
        payload="' OR 1=1 --",
        vulnerable_rows=[(1, "alice")],
        patched_rows=[],
        baseline_exploitable=True,
        patch_blocks_payload=True,
        passed=True,
        details="Controlled fixture execution",
    )

    decision = planner.plan(results=[r1, r2])
    assert decision.action == "STOP_INCONCLUSIVE"
    assert "budget has been reached" in decision.reason


# -----------------------------------------------------------------------------
# 5. Coverage Tracking & Unsupported Handling
# -----------------------------------------------------------------------------

def test_coverage_tracking_and_not_applicable_tests():
    """Verify that get_coverage tracks executed, passed, failed, not applicable, and gaps."""
    planner = AgentPlanner(max_tests=5)

    r1 = LocalAppTestResult(
        test_id="SQLI_QUOTE_001",
        payload="' OR '1'='1",
        target_type="REAL_LOCAL_APPLICATION",
        target_provenance="LOCAL_SQLITE_INSTANCE",
        submitted_source_executed=True,
        source_runtime_match=True,
        vulnerable_rows=[{"username": "alice"}],
        patched_rows=[],
        functionality_check_rows=[{"username": "alice"}],
        baseline_exploitable=True,
        patch_blocks_payload=True,
        functionality_intact=True,
        passed=True,
        outcome="PASS",
        observed_behavior="Blocked",
        expected_behavior="Blocked",
        category=SQLInjectionCategory.QUOTE_DELIMITER.value,
        security_invariant="UNTRUSTED_INPUT_CANNOT_ESCAPE_STRING_DELIMITER",
    )

    coverage = planner.get_coverage([r1])
    assert coverage.tests_available == 40
    assert coverage.tests_executed == 1
    assert coverage.tests_passed == 1
    assert coverage.tests_failed == 0
    assert coverage.tests_not_applicable == 3  # Stacked queries
    assert SQLInjectionCategory.QUOTE_DELIMITER.value in coverage.categories_covered
    assert "UNTRUSTED_INPUT_CANNOT_ESCAPE_STRING_DELIMITER" in coverage.invariants_verified
    assert len(coverage.remaining_coverage_gaps) > 0


# -----------------------------------------------------------------------------
# 6. End-to-End Agent Loop with Coverage
# -----------------------------------------------------------------------------

def test_end_to_end_adaptive_verification_loop_with_coverage():
    """Run full agent loop with PatchedUserApp and verify coverage and verdict."""
    vuln_app = VulnerableUserApp()
    patch_app = PatchedUserApp()

    try:
        agent = MoriartyAgentLoop(max_tests=5)
        response = agent.run(
            original_source=vuln_app.source_code,
            patched_source=patch_app.source_code,
            vulnerable_app=vuln_app,
            patched_app=patch_app,
        )

        assert response.verdict == "VERIFIED"
        assert response.coverage is not None
        assert response.coverage.tests_executed == 5
        assert response.coverage.tests_passed == 5
        assert response.coverage.tests_not_applicable == 3
        assert len(response.coverage.categories_covered) >= 2
        assert len(response.coverage.invariants_verified) >= 2

        # Verify decision trace contains dynamic adaptive reasoning
        assert len(response.decision_trace) >= 5
        for step in response.decision_trace:
            assert "step" in step
            assert "action" in step
            assert "reason" in step
    finally:
        vuln_app.close()
        patch_app.close()


def test_end_to_end_incomplete_patch_rejected():
    """Incomplete patch is rejected by adaptive agent loop with failing test and coverage."""
    vuln_app = VulnerableUserApp()
    bad_patch_app = IncompletePatchUserApp()

    try:
        agent = MoriartyAgentLoop(max_tests=5)
        response = agent.run(
            original_source=vuln_app.source_code,
            patched_source=bad_patch_app.source_code,
            vulnerable_app=vuln_app,
            patched_app=bad_patch_app,
        )

        assert response.verdict == "REJECTED"
        assert response.coverage is not None
        assert response.coverage.tests_failed >= 1
    finally:
        vuln_app.close()
        bad_patch_app.close()
