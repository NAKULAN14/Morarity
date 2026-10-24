from app.agent.planner import AgentPlanner
from app.execution.differential_runner import DifferentialTestResult


def test_planner_chooses_fallback_when_baseline_not_exploitable():
    planner = AgentPlanner(max_tests=3)

    previous_result = DifferentialTestResult(
        payload="' OR '1'='1",
        vulnerable_rows=[(1, "alice")],
        patched_rows=[(1, "alice")],
        baseline_exploitable=False,
        patch_blocks_payload=True,
        passed=True,
        details="Baseline exploitability was not demonstrated.",
    )

    decision = planner.plan([previous_result])

    assert decision.action == "RUN_TEST"
    assert decision.strategy == "BOOLEAN_TRUE"
    assert decision.next_payload == "' OR 1=1 --"


def test_planner_prioritizes_unsafe_query_finding():
    """Requirement 4: Planner handles SQLI_UNSAFE_QUERY."""
    planner = AgentPlanner(max_tests=3)
    decision = planner.plan(
        results=[],
        patched_rule_ids=["SQLI_UNSAFE_QUERY"],
        patch_status="VULNERABILITY_REMAINS",
    )

    assert decision.action == "RUN_TEST"
    assert "SQLI_UNSAFE_QUERY" in decision.reason
    assert "potentially unsafe query construction" in decision.reason


def test_planner_recognizes_parameterized_query_without_trusting():
    """Requirement 4: Planner handles SQLI_PARAMETERIZED_QUERY without treating as runtime proof."""
    planner = AgentPlanner(max_tests=3)
    decision = planner.plan(
        results=[],
        patched_rule_ids=["SQLI_PARAMETERIZED_QUERY"],
        patch_status="PATCH_PATTERN_IMPROVED",
    )

    assert decision.action == "RUN_TEST"
    assert "SQLI_PARAMETERIZED_QUERY" in decision.reason
    assert "does not prove runtime security" in decision.reason


def test_planner_recognizes_static_query():
    """Requirement 4: Planner handles SQLI_STATIC_QUERY."""
    planner = AgentPlanner(max_tests=3)
    decision = planner.plan(
        results=[],
        patched_rule_ids=["SQLI_STATIC_QUERY"],
    )

    assert decision.action == "RUN_TEST"
    assert "SQLI_STATIC_QUERY" in decision.reason
    assert "statically constructed" in decision.reason


def test_planner_preserves_uncertainty_on_unknown_finding():
    """Requirement 4: Planner handles SQLI_UNKNOWN_QUERY by preserving uncertainty."""
    planner = AgentPlanner(max_tests=3)
    decision = planner.plan(
        results=[],
        patched_rule_ids=["SQLI_UNKNOWN_QUERY"],
    )

    assert decision.action == "STOP_INCONCLUSIVE"
    assert "SQLI_UNKNOWN_QUERY" in decision.reason
    assert "preserves uncertainty" in decision.reason


def test_planner_handles_unsupported_analysis():
    """Requirement 4: Planner handles ANALYSIS_UNSUPPORTED."""
    planner = AgentPlanner(max_tests=3)
    decision = planner.plan(
        results=[],
        patch_status="ANALYSIS_UNSUPPORTED",
    )

    assert decision.action == "STOP_INCONCLUSIVE"
    assert "unsupported" in decision.reason.lower()


def test_planner_enforces_budget():
    """Requirement 10: Test budget enforcement."""
    planner = AgentPlanner(max_tests=2)
    fake_results = [
        DifferentialTestResult(
            payload="p1", vulnerable_rows=[(1,)], patched_rows=[],
            baseline_exploitable=True, patch_blocks_payload=True, passed=True, details="ok"
        ),
        DifferentialTestResult(
            payload="p2", vulnerable_rows=[(1,)], patched_rows=[],
            baseline_exploitable=True, patch_blocks_payload=True, passed=True, details="ok"
        ),
    ]

    decision = planner.plan(fake_results)
    assert decision.action == "STOP_INCONCLUSIVE"
    assert "budget" in decision.reason.lower()
