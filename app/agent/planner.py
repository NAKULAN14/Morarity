
from dataclasses import dataclass

from app.execution.differential_runner import DifferentialTestResult


@dataclass
class PlanDecision:
    action: str
    reason: str
    next_payload: str | None = None
    strategy: str | None = None


class AgentPlanner:
    """
    Observation-based planner for Moriarty.
    """

    def __init__(self, max_tests: int = 3) -> None:
        self.max_tests = max_tests

        self.boolean_strategies = [
            {
                "name": "BOOLEAN_OR",
                "payload": "' OR '1'='1",
            },
            {
                "name": "BOOLEAN_COMMENT",
                "payload": "' OR 1=1 --",
            },
            {
                "name": "BOOLEAN_ADMIN",
                "payload": "admin' OR '1'='1' --",
            },
        ]

        self.fallback_strategies = [
            {
                "name": "BOOLEAN_TRUE",
                "payload": "' OR 1=1 --",
            },
            {
                "name": "BOOLEAN_FALSE",
                "payload": "' AND 1=2 --",
            },
        ]

    def plan(
        self,
        results: list[DifferentialTestResult],
    ) -> PlanDecision:

        # Stop if a test encountered an error.
        for result in results:
            if result.error:
                return PlanDecision(
                    action="STOP_FOR_INVESTIGATION",
                    reason=(
                        "A test encountered an execution error. "
                        "The agent must investigate before continuing."
                    ),
                )

        # Stop if the expected differential behavior was not observed.
        for result in results:
            if not result.passed:
                return PlanDecision(
                    action="STOP_FOR_INVESTIGATION",
                    reason=(
                        "The expected vulnerable-versus-patched "
                        "behavior was not observed. "
                        "The agent must investigate."
                    ),
                )

        # Stop when the testing budget is exhausted.
        if len(results) >= self.max_tests:
            return PlanDecision(
                action="STOP_INCONCLUSIVE",
                reason=(
                    "The testing budget has been reached. "
                    "The available evidence is not sufficient "
                    "to verify the submitted patch."
                ),
            )

        # First test: start with a boolean-based strategy.
        if not results:
            next_strategy = self.boolean_strategies[0]

            return PlanDecision(
                action="RUN_TEST",
                reason=(
                    "No tests have been executed yet. "
                    "The agent is starting with a boolean-based test."
                ),
                next_payload=next_strategy["payload"],
                strategy=next_strategy["name"],
            )

        previous = results[-1]

        # If the baseline was exploitable and the patch blocked it,
        # continue with the next boolean strategy.
        if (
            previous.baseline_exploitable
            and previous.patch_blocks_payload
        ):
            used_payloads = {
                result.payload for result in results
            }

            for strategy in self.boolean_strategies:
                if strategy["payload"] not in used_payloads:
                    return PlanDecision(
                        action="RUN_TEST",
                        reason=(
                            "The previous payload exploited the "
                            "baseline but was blocked by the patch. "
                            "The agent is trying another boolean strategy."
                        ),
                        next_payload=strategy["payload"],
                        strategy=strategy["name"],
                    )

        # If the baseline was not exploitable, use a fallback strategy.
        if not previous.baseline_exploitable:
            used_payloads = {
                result.payload for result in results
            }

            for strategy in self.fallback_strategies:
                if strategy["payload"] not in used_payloads:
                    return PlanDecision(
                        action="RUN_TEST",
                        reason=(
                            "The previous payload did not demonstrate "
                            "baseline exploitability. The agent is "
                            "trying an alternative boolean strategy."
                        ),
                        next_payload=strategy["payload"],
                        strategy=strategy["name"],
                    )

        return PlanDecision(
            action="STOP_INCONCLUSIVE",
            reason=(
                "No unused strategy is available for the observed "
                "behavior. More testing is required."
            ),
        )
