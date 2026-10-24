
from dataclasses import dataclass

from app.agent.planner import AgentPlanner
from app.execution.differential_runner import (
    DifferentialSQLRunner,
    DifferentialTestResult,
)
from app.verification.evidence_ledger import EvidenceLedger


@dataclass
class AgentLoopResult:
    tests_executed: list[DifferentialTestResult]
    evidence: list
    final_action: str
    final_reason: str


class MoriartyAgentLoop:
    def __init__(self, max_tests: int = 3) -> None:
        self.planner = AgentPlanner(max_tests=max_tests)
        self.runner = DifferentialSQLRunner()
        self.ledger = EvidenceLedger()

    def run(self) -> AgentLoopResult:
        results: list[DifferentialTestResult] = []

        while True:
            decision = self.planner.plan(results)

            print("\nAgent action:", decision.action)
            print("Reason:", decision.reason)

            if decision.action != "RUN_TEST":
                break

            payload = decision.next_payload

            if payload is None:
                break

            print("Selected strategy:", decision.strategy)
            print("Selected payload:", payload)

            # Run the differential test and retain its full observations.
            differential_result = self.runner.run(payload)

            results.append(differential_result)

            # Convert the differential result for the existing evidence ledger.
            test_result = self.runner.run_as_test_result(payload)

            evidence = self.ledger.record(test_result)

            print("Test outcome:", test_result.outcome)
            print("Test passed:", test_result.passed)
            print("Baseline exploitable:", differential_result.baseline_exploitable)
            print("Patch blocks payload:", differential_result.patch_blocks_payload)
            print("Evidence recorded:", evidence.evidence_id)

        return AgentLoopResult(
            tests_executed=results,
            evidence=self.ledger.get_all(),
            final_action=decision.action,
            final_reason=decision.reason,
        )
