
from app.agent.planner import AgentPlanner
from app.models.schemas import TestResult


planner = AgentPlanner(max_tests=3)

results = []

for step in range(4):
    decision = planner.plan(results)

    print(f"\nStep {step + 1}")
    print("Action:", decision.action)
    print("Reason:", decision.reason)

    if decision.action != "RUN_TEST":
        break

    print("Payload:", decision.next_payload)

    # Simulate a successful test execution.
    # This is only to test the planner's decision logic.
    results.append(
        TestResult(
            test_id=f"TEST_{step + 1}",
            passed=True,
            outcome="PASS",
            details="Test executed successfully.",
        )
    )
