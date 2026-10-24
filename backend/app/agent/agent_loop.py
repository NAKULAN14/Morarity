import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from app.agent.planner import AgentPlanner
from app.execution.differential_runner import (
    DifferentialSQLRunner,
    DifferentialTestResult,
)
from app.execution.local_app_runner import (
    LocalAppVerificationRunner,
    LocalAppTestResult,
)
from app.execution.source_executor import (
    ControlledSourceExecutor,
    SourceBoundUserApp,
    verify_target_provenance,
)
from app.models.schemas import (
    AnalysisResult,
    Evidence,
    FunctionalityInvariant,
    TestResult,
    Verdict,
    VerificationResponse,
)
from app.reporting.report_generator import ReportGenerator
from app.verification.evidence_ledger import EvidenceLedger
from app.verification.verdict_engine import VerdictEngine
from app.verification.patch_comparator import (
    PatchComparator,
    PatchComparisonResult,
)


@dataclass
class AgentLoopResult:
    tests_executed: list[Any]
    evidence: list[Evidence]
    final_action: str
    final_reason: str
    verdict: Verdict
    verdict_summary: str
    patch_comparison: Optional[PatchComparisonResult] = None
    decision_trace: Optional[list[dict]] = None
    target_type: str = "CONTROLLED_FIXTURE"
    target_provenance: str = "DEMO_FIXTURE"
    submitted_source_executed: bool = False
    source_runtime_match: bool = False
    dynamic_verification_performed: bool = False
    stopping_reason: Optional[str] = None
    verification_response: Optional[VerificationResponse] = None


class MoriartyAgentLoop:
    """
    Adaptive, finding-aware, bounded verification loop for Moriarty.

    Executes controlled tests against local applications, submitted-source runtime targets,
    or differential fixtures, records empirical observations in an evidence ledger,
    and computes an explainable verdict with rigorous source-to-runtime integrity.
    """

    def __init__(self, max_tests: int = 3) -> None:
        self.max_tests = max_tests
        self.planner = AgentPlanner(max_tests=max_tests)
        self.runner = DifferentialSQLRunner()
        self.ledger = EvidenceLedger()
        self.verdict_engine = VerdictEngine()
        self.patch_comparator = PatchComparator()
        self.report_generator = ReportGenerator()

    def run(
        self,
        original_source: Optional[str] = None,
        patched_source: Optional[str] = None,
        report_path: Optional[str] = "reports/moriarty_report.json",
        vulnerable_app: Optional[Any] = None,
        patched_app: Optional[Any] = None,
        execute_submitted_source: bool = False,
        functionality_invariant: Optional[FunctionalityInvariant] = None,
        require_functionality_invariant: bool = True,
        max_execution_time_seconds: Optional[float] = 10.0,
    ) -> AgentLoopResult:
        loop_start_time = time.perf_counter()
        results: list[Any] = []
        decision_trace: list[dict] = []
        self.ledger.clear()

        patch_comparison: Optional[PatchComparisonResult] = None
        orig_rule_ids: list[str] = []
        patch_rule_ids: list[str] = []

        dynamically_created_apps: list[Any] = []

        # 1. Establish Source-to-Runtime Relationship and Provenance
        if vulnerable_app is not None and patched_app is not None:
            # Case A: Explicit runtime applications were provided.
            # Verify whether their provenance corresponds to the submitted source.
            match_orig, t_type1, prov1, sub_exec1 = verify_target_provenance(original_source, vulnerable_app)
            match_patch, t_type2, prov2, sub_exec2 = verify_target_provenance(patched_source, patched_app)

            source_runtime_match = match_orig and match_patch
            submitted_source_executed = sub_exec1 and sub_exec2
            target_type = "REAL_LOCAL_APPLICATION"
            target_provenance = prov2 if source_runtime_match else "PROVENANCE_MISMATCH"
            active_vuln_app = vulnerable_app
            active_patched_app = patched_app
            is_dynamic_target = True

        elif execute_submitted_source and original_source is not None and patched_source is not None:
            # Case B: Direct submitted-source execution requested.
            # Safely compile the submitted sources in an isolated test environment.
            src_app_vuln, msg_v = ControlledSourceExecutor.create_app_from_source(original_source)
            src_app_patch, msg_p = ControlledSourceExecutor.create_app_from_source(patched_source)

            if src_app_vuln is not None and src_app_patch is not None:
                dynamically_created_apps.extend([src_app_vuln, src_app_patch])
                active_vuln_app = src_app_vuln
                active_patched_app = src_app_patch
                target_type = "SUBMITTED_SOURCE_EXECUTION"
                target_provenance = "RESTRICTED_SOURCE_ENV"
                submitted_source_executed = True
                source_runtime_match = True
                is_dynamic_target = True
            else:
                # Submitted source could not be instantiated safely
                active_vuln_app = None
                active_patched_app = None
                target_type = "SUBMITTED_SOURCE_EXECUTION"
                target_provenance = "SOURCE_EXECUTION_UNSUPPORTED"
                submitted_source_executed = False
                source_runtime_match = False
                is_dynamic_target = False

        else:
            # Case C: No runtime target provided and execute_submitted_source is False.
            # Runs controlled in-memory demonstration fixture only.
            active_vuln_app = None
            active_patched_app = None
            target_type = "CONTROLLED_FIXTURE"
            target_provenance = "DEMO_FIXTURE"
            submitted_source_executed = False
            source_runtime_match = False
            is_dynamic_target = False

        try:
            # 2. Static Patch Analysis and Comparison
            if original_source is not None and patched_source is not None:
                patch_comparison = self.patch_comparator.compare(
                    original_source=original_source,
                    patched_source=patched_source,
                )
                orig_rule_ids = patch_comparison.original_rule_ids
                patch_rule_ids = patch_comparison.patched_rule_ids

                self.ledger.record_patch_comparison(patch_comparison)

                print("\n--- Static Patch Comparison ---")
                print("Status:", patch_comparison.status)
                print("Summary:", patch_comparison.summary)
                print("Original findings:", orig_rule_ids)
                print("Patched findings:", patch_rule_ids)
                print("Static improvement detected:", patch_comparison.static_improvement_detected)
                print("Dynamic verification performed:", patch_comparison.dynamic_verification_performed)

            elif original_source is not None or patched_source is not None:
                print("\nStatic patch comparison skipped: both original and patched sources are required.")

            # Construct dynamic runner if a valid local target is active
            real_runner = (
                LocalAppVerificationRunner(
                    vulnerable_app=active_vuln_app,
                    patched_app=active_patched_app,
                    functionality_invariant=functionality_invariant,
                    require_functionality_invariant=require_functionality_invariant,
                    target_type=target_type,
                    target_provenance=target_provenance,
                    submitted_source_executed=submitted_source_executed,
                    source_runtime_match=source_runtime_match,
                )
                if (is_dynamic_target and active_vuln_app and active_patched_app)
                else None
            )

            # 3. Bounded Agent Verification Loop
            stopping_reason: Optional[str] = None

            while True:
                # Check execution time budget if specified
                if max_execution_time_seconds is not None:
                    elapsed = time.perf_counter() - loop_start_time
                    if elapsed > max_execution_time_seconds:
                        stopping_reason = "EXECUTION_TIME_BUDGET_EXCEEDED"
                        decision_trace.append({
                            "step": len(decision_trace) + 1,
                            "patch_status": patch_comparison.status if patch_comparison else None,
                            "analyzer_findings": patch_rule_ids,
                            "action": "STOP_INCONCLUSIVE",
                            "strategy": None,
                            "reason": f"Execution time budget exceeded ({elapsed:.2f}s > {max_execution_time_seconds}s).",
                            "test_input": None,
                            "test_outcome": None,
                            "evidence_id": None,
                            "stop_reason": "Time budget exhausted",
                        })
                        break

                # Find next action using finding-aware planner
                decision = self.planner.plan(
                    results=results,
                    patch_status=patch_comparison.status if patch_comparison else None,
                    original_rule_ids=orig_rule_ids,
                    patched_rule_ids=patch_rule_ids,
                )

                step_entry = {
                    "step": len(decision_trace) + 1,
                    "patch_status": patch_comparison.status if patch_comparison else None,
                    "analyzer_findings": patch_rule_ids,
                    "action": decision.action,
                    "strategy": decision.strategy,
                    "reason": decision.reason,
                    "test_input": decision.next_payload,
                    "test_outcome": None,
                    "evidence_id": None,
                    "stop_reason": decision.reason if decision.action.startswith("STOP") else None,
                }
                decision_trace.append(step_entry)

                print(f"\n[Agent Step {step_entry['step']}] Action: {decision.action}")
                print(f"Reason: {decision.reason}")

                if decision.action != "RUN_TEST":
                    stopping_reason = decision.stopping_reason or decision.action
                    break

                payload = decision.next_payload
                if payload is None:
                    step_entry["action"] = "STOP_INCONCLUSIVE"
                    step_entry["stop_reason"] = "Planner requested test execution without providing payload."
                    stopping_reason = "MISSING_PAYLOAD"
                    break

                print(f"Selected Strategy: {decision.strategy} | Payload: {payload}")

                # Execute test against local dynamic runner or simulated fixture
                if real_runner is not None:
                    test_id = f"SQLI_REAL_APP_{len(results) + 1:03d}"
                    real_result = real_runner.run_test(payload=payload, test_id=test_id)
                    results.append(real_result)

                    evidence = self.ledger.record_local_app_test(real_result)
                    step_entry["test_outcome"] = real_result.outcome
                    step_entry["evidence_id"] = evidence.evidence_id

                    print(f"Test outcome: {real_result.outcome} (Passed={real_result.passed})")
                    print(f"Baseline exploitable: {real_result.baseline_exploitable} | Patch blocks: {real_result.patch_blocks_payload}")
                    print(f"Functionality intact: {real_result.functionality_intact}")
                    print(f"Target Provenance: {target_provenance} (Match={source_runtime_match})")
                    print(f"Evidence recorded: {evidence.evidence_id} [supports_verification={evidence.supports_verification}]")

                else:
                    test_id = f"SQLI_DIFFERENTIAL_{len(results) + 1:03d}"
                    diff_result = self.runner.run(payload)
                    results.append(diff_result)

                    outcome = "ERROR" if diff_result.error else ("PASS" if diff_result.passed else "FAIL")
                    test_result = TestResult(
                        test_id=test_id,
                        passed=diff_result.passed,
                        outcome=outcome,
                        details=(
                            f"{diff_result.details} "
                            f"Vulnerable rows: {len(diff_result.vulnerable_rows)}. "
                            f"Patched rows: {len(diff_result.patched_rows)}."
                        ),
                        error=diff_result.error,
                        baseline_exploitable=diff_result.baseline_exploitable,
                        patch_blocks_payload=diff_result.patch_blocks_payload,
                    )
                    evidence = self.ledger.record(test_result, category="CONTROLLED_DEMONSTRATION", supports_verification=False)
                    step_entry["test_outcome"] = outcome
                    step_entry["evidence_id"] = evidence.evidence_id

                    print(f"Test outcome: {outcome}")
                    print(f"Baseline exploitable: {diff_result.baseline_exploitable} | Patch blocks: {diff_result.patch_blocks_payload}")
                    print(f"Evidence recorded: {evidence.evidence_id} (Controlled demonstration only)")

            # 4. Determine Final Verdict from Collected Evidence
            all_evidence = self.ledger.get_all()
            verdict, verdict_summary = self.verdict_engine.decide(all_evidence)

            # Ensure harmony between verdict, final action, and stopping reason
            last_decision = decision_trace[-1] if decision_trace else {}
            final_action = last_decision.get("action", "STOP_INCONCLUSIVE")
            final_reason = last_decision.get("reason", verdict_summary)

            if verdict == Verdict.VERIFIED:
                final_action = "STOP_VERIFIED"
                stopping_reason = "VERIFICATION_REQUIREMENTS_SATISFIED"
            elif verdict == Verdict.REJECTED:
                final_action = "STOP_REJECTED"
                stopping_reason = "VULNERABILITY_REMAINS_EXPLOITABLE"
            elif verdict == Verdict.INCONCLUSIVE and not final_action.startswith("STOP"):
                final_action = "STOP_INCONCLUSIVE"
                stopping_reason = stopping_reason or "INSUFFICIENT_EVIDENCE"

            # 5. Format Test Results for Report
            report_tests: list[TestResult] = []
            for index, res in enumerate(results, start=1):
                if isinstance(res, LocalAppTestResult):
                    report_tests.append(res.to_test_result())
                elif isinstance(res, DifferentialTestResult):
                    outcome = "ERROR" if res.error else ("PASS" if res.passed else "FAIL")
                    report_tests.append(
                        TestResult(
                            test_id=f"SQLI_DIFFERENTIAL_{index:03d}",
                            passed=res.passed,
                            outcome=outcome,
                            details=res.details,
                            error=res.error,
                            baseline_exploitable=res.baseline_exploitable,
                            patch_blocks_payload=res.patch_blocks_payload,
                        )
                    )
                elif isinstance(res, TestResult):
                    report_tests.append(res)

            # 6. Build Analysis Summary for Report
            if patch_comparison is not None:
                patched_analysis = patch_comparison.patched_analysis
                analysis = AnalysisResult(
                    supported=patched_analysis.supported,
                    vulnerability_type=patched_analysis.vulnerability_type,
                    findings=patched_analysis.findings,
                    security_invariants=patched_analysis.security_invariants,
                    summary=patched_analysis.summary,
                )
                patch_comparison.dynamic_verification_performed = is_dynamic_target and len(results) > 0
            else:
                analysis = AnalysisResult(
                    supported=False,
                    vulnerability_type=None,
                    findings=[],
                    security_invariants=[],
                    summary="No original-versus-patched source comparison was supplied.",
                )

            limitations = [
                "Static source comparison does not establish runtime security.",
                "A VERIFIED verdict requires empirical evidence that directly supports the relevant security invariants.",
                "Scope of verification is restricted to the specific SQL query execution path tested.",
            ]
            if not is_dynamic_target:
                limitations.append("Controlled demonstration tests executed against simulated fixtures; submitted application code was not executed.")
            elif not source_runtime_match:
                limitations.append("Target provenance mismatch: executed runtime target could not be verified to correspond to submitted source.")

            verification_response = VerificationResponse(
                verification_id=str(uuid4()),
                verdict=verdict,
                summary=verdict_summary,
                analysis=analysis,
                tests_executed=report_tests,
                evidence=all_evidence,
                limitations=limitations,
                verification_scope=(
                    "Targeted local SQLite user search query path"
                    if is_dynamic_target
                    else "Simulated demonstration fixture only"
                ),
                dynamic_verification_performed=is_dynamic_target and len(results) > 0,
                target_type=target_type,
                target_provenance=target_provenance,
                submitted_source_executed=submitted_source_executed,
                source_runtime_match=source_runtime_match,
                final_action=final_action,
                stopping_reason=stopping_reason,
                decision_trace=decision_trace,
                patch_comparison={
                    "status": patch_comparison.status,
                    "summary": patch_comparison.summary,
                    "original_rule_ids": patch_comparison.original_rule_ids,
                    "patched_rule_ids": patch_comparison.patched_rule_ids,
                    "static_improvement_detected": patch_comparison.static_improvement_detected,
                    "dynamic_verification_performed": patch_comparison.dynamic_verification_performed,
                } if patch_comparison else None,
            )

            # 7. Generate JSON Report
            report = self.report_generator.generate(
                response=verification_response,
                output_path=None,
                patch_comparison=patch_comparison,
            )

            report["agent"] = {
                "final_action": final_action,
                "final_reason": final_reason,
                "stopping_reason": stopping_reason,
                "tests_run": len(results),
                "decision_trace": decision_trace,
            }

            if report_path is not None:
                path = Path(report_path)
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("w", encoding="utf-8") as file:
                    json.dump(report, file, indent=4, ensure_ascii=False)

                print("\n--- Report Generated ---")
                print("Report path:", path)
                print("Final verdict:", verdict.value)
                print("Final action:", final_action)
                print("Stopping reason:", stopping_reason)
                print("Verdict summary:", verdict_summary)

            return AgentLoopResult(
                tests_executed=results,
                evidence=all_evidence,
                final_action=final_action,
                final_reason=final_reason,
                verdict=verdict,
                verdict_summary=verdict_summary,
                patch_comparison=patch_comparison,
                decision_trace=decision_trace,
                target_type=target_type,
                target_provenance=target_provenance,
                submitted_source_executed=submitted_source_executed,
                source_runtime_match=source_runtime_match,
                dynamic_verification_performed=is_dynamic_target and len(results) > 0,
                stopping_reason=stopping_reason,
                verification_response=verification_response,
            )

        finally:
            # Clean up temporary resources
            for app in dynamically_created_apps:
                if hasattr(app, "close"):
                    try:
                        app.close()
                    except Exception:
                        pass
