
from uuid import uuid4

from app.analyzer.ast_analyzer import SQLInjectionAnalyzer
from app.analyzer.invariants import SecurityInvariantGenerator
from app.agent.selector import AdaptiveTestSelector
from app.execution.runner import VerificationTestRunner
from app.execution.differential_runner import DifferentialSQLRunner
from app.models.schemas import (
    VerificationRequest,
    VerificationResponse,
    Verdict,
)
from app.verification.evidence_ledger import EvidenceLedger
from app.verification.verdict_engine import VerdictEngine


class VerificationController:
    """
    Coordinates the complete Moriarty verification workflow.

    Current limitation:
    Differential tests run against a controlled SQLite demonstration.
    They do not execute the submitted source code.
    """

    def __init__(self) -> None:
        self.analyzer = SQLInjectionAnalyzer()
        self.invariant_generator = SecurityInvariantGenerator()
        self.test_selector = AdaptiveTestSelector()
        self.test_runner = VerificationTestRunner()
        self.differential_runner = DifferentialSQLRunner()
        self.verdict_engine = VerdictEngine()

    def verify(
        self,
        request: VerificationRequest,
    ) -> VerificationResponse:
        verification_id = str(uuid4())

        # 1. Analyze the submitted source code.
        analysis = self.analyzer.analyze(request.source_code)

        # 2. Stop if the analyzer cannot process the source.
        if not analysis.supported:
            return VerificationResponse(
                verification_id=verification_id,
                verdict=Verdict.INCONCLUSIVE,
                summary=analysis.summary,
                analysis=analysis,
                tests_executed=[],
                evidence=[],
                limitations=[
                    "The submitted source could not be analyzed.",
                ],
            )

        # 3. Generate security invariants.
        analysis.security_invariants = (
            self.invariant_generator.generate(analysis)
        )

        # 4. Select tests based on the analysis and scenario.
        selected_tests = self.test_selector.select_tests(
            analysis=analysis,
            scenario=request.scenario,
        )

        # 5. Execute the existing controlled test runner.
        test_results = self.test_runner.run_tests(selected_tests)

        # 6. Run a differential SQL injection demonstration
        #    when SQL injection is identified.
        if analysis.vulnerability_type == "SQL_INJECTION":
            differential_result = (
                self.differential_runner.run_as_test_result()
            )
            test_results.append(differential_result)

        # 7. Record results in the evidence ledger.
        ledger = EvidenceLedger()
        evidence = ledger.record_many(test_results)

        # 8. Determine the verdict.
        verdict, verdict_summary = self.verdict_engine.decide(evidence)

        # 9. Report limitations honestly.
        limitations = [
            (
                "The current runner uses controlled in-memory SQLite "
                "demonstrations rather than executing the submitted code."
            ),
            (
                "The differential SQL test compares a hardcoded vulnerable "
                "query with a parameterized demonstration query."
            ),
            (
                "Passing demonstration tests do not establish that the "
                "submitted patch is secure."
            ),
            (
                "Functionality and scenario tests are selected but are "
                "not supported by the current runner."
            ),
        ]

        if analysis.vulnerability_type is None:
            limitations.append(
                "No recognized SQL injection execution path was identified."
            )

        return VerificationResponse(
            verification_id=verification_id,
            verdict=verdict,
            summary=verdict_summary,
            analysis=analysis,
            tests_executed=test_results,
            evidence=evidence,
            limitations=limitations,
        )


def verify_request(
    request: VerificationRequest,
) -> VerificationResponse:
    """
    Convenience function for API routes and other modules.
    """
    return VerificationController().verify(request)
