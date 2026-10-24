
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
