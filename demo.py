"""
Moriarty — Agentic AI Structural Security Patch Verification
Hackathon Demonstration Entrypoint

Demonstrates end-to-end adaptive security patch verification across 4 key scenarios:
1. Real Local SQLite Application with Valid Patch -> VERIFIED (provenance verified)
2. Real Local SQLite Application with Incomplete Patch -> REJECTED (fix disproved)
3. Controlled Demonstration Fixture Only -> INCONCLUSIVE (preserves honesty, prevents false positives)
4. Direct Submitted-Source Isolated Execution -> VERIFIED (submitted source dynamically compiled & verified)
"""

import sys
from pathlib import Path

# Ensure backend package is in python path
backend_path = Path(__file__).resolve().parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.agent.agent_loop import MoriartyAgentLoop
from app.scenarios.vulnerable import VulnerableUserApp, SOURCE_CODE as VULN_SOURCE
from app.scenarios.correct_patch import PatchedUserApp, SOURCE_CODE as PATCH_SOURCE
from app.scenarios.incomplete_patch import IncompletePatchUserApp, SOURCE_CODE as INCOMPLETE_SOURCE


def print_header(title: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {title.upper()}")
    print("=" * 78)


def run_demo() -> None:
    print_header("Moriarty — Adaptive AI Security Patch Verification Agent")
    print("Central Principle: Disprove the claim that a vulnerability has been fixed")
    print("before allowing that claim to be marked VERIFIED.\n")

    # =========================================================================
    # SCENARIO 1: Real Local Application — Valid Parameterized Patch (VERIFIED)
    # =========================================================================
    print_header("Scenario 1: Real Local SQLite Application — Valid Parameterized Patch")
    print("Target: Intentionally vulnerable local SQLite user lookup service")
    print("Expected: Agent challenges patch with controlled payloads, observes safe handling,")
    print("checks functionality preservation, and issues VERIFIED with explicit scope.\n")

    vuln_app = VulnerableUserApp()
    patch_app = PatchedUserApp()

    try:
        agent = MoriartyAgentLoop(max_tests=3)
        result1 = agent.run(
            original_source=vuln_app.source_code,
            patched_source=patch_app.source_code,
            vulnerable_app=vuln_app,
            patched_app=patch_app,
            report_path="reports/demo_verified_report.json",
        )

        print("\n--- Scenario 1 Decision Trace ---")
        if result1.decision_trace:
            for step in result1.decision_trace:
                outcome_str = f" | Outcome: {step.get('test_outcome')}" if step.get("test_outcome") else ""
                print(f"Step {step['step']}: Action={step['action']} | Strategy={step['strategy']}{outcome_str}")
                print(f"       Reason: {step['reason']}")

        print(f"\nFinal Verdict: [{result1.verdict.value}]")
        print(f"Final Action:  [{result1.final_action}]")
        print(f"Stopping Reason: [{result1.stopping_reason}]")
        print(f"Target Provenance: [{result1.target_provenance}] (Match={result1.source_runtime_match})")
        print(f"Summary: {result1.verdict_summary}")

    finally:
        vuln_app.close()
        patch_app.close()

    # =========================================================================
    # SCENARIO 2: Real Local Application — Incomplete Patch (REJECTED)
    # =========================================================================
    print_header("Scenario 2: Real Local SQLite Application — Incomplete Patch")
    print("Target: Application using naive sanitization (replace '--' only)")
    print("Expected: Agent discovers vulnerability remains exploitable and REJECTS the patch.\n")

    vuln_app2 = VulnerableUserApp()
    incomplete_app = IncompletePatchUserApp()

    try:
        agent2 = MoriartyAgentLoop(max_tests=3)
        result2 = agent2.run(
            original_source=vuln_app2.source_code,
            patched_source=incomplete_app.source_code,
            vulnerable_app=vuln_app2,
            patched_app=incomplete_app,
            report_path="reports/demo_rejected_report.json",
        )

        print("\n--- Scenario 2 Decision Trace ---")
        if result2.decision_trace:
            for step in result2.decision_trace:
                outcome_str = f" | Outcome: {step.get('test_outcome')}" if step.get("test_outcome") else ""
                print(f"Step {step['step']}: Action={step['action']} | Strategy={step['strategy']}{outcome_str}")
                print(f"       Reason: {step['reason']}")

        print(f"\nFinal Verdict: [{result2.verdict.value}]")
        print(f"Final Action:  [{result2.final_action}]")
        print(f"Stopping Reason: [{result2.stopping_reason}]")
        print(f"Target Provenance: [{result2.target_provenance}] (Match={result2.source_runtime_match})")
        print(f"Summary: {result2.verdict_summary}")

    finally:
        vuln_app2.close()
        incomplete_app.close()

    # =========================================================================
    # SCENARIO 3: Controlled Demonstration Fixture Only (INCONCLUSIVE)
    # =========================================================================
    print_header("Scenario 3: Controlled Fixture Testing — Honesty Enforcement")
    print("Target: Controlled in-memory demonstration without real application execution")
    print("Expected: Agent passes tests but refuses false safety, issuing INCONCLUSIVE.\n")

    agent3 = MoriartyAgentLoop(max_tests=3)
    result3 = agent3.run(
        original_source=VULN_SOURCE,
        patched_source=PATCH_SOURCE,
        vulnerable_app=None,
        patched_app=None,
        report_path="reports/demo_inconclusive_report.json",
    )

    print(f"\nFinal Verdict: [{result3.verdict.value}]")
    print(f"Final Action:  [{result3.final_action}]")
    print(f"Stopping Reason: [{result3.stopping_reason}]")
    print(f"Summary: {result3.verdict_summary}")

    # =========================================================================
    # SCENARIO 4: Direct Submitted-Source Isolated Execution (VERIFIED)
    # =========================================================================
    print_header("Scenario 4: Direct Submitted-Source Isolated Execution")
    print("Target: Submitted Python source safely compiled in isolated environment")
    print("Expected: Agent validates AST, executes submitted code, and establishes provenance.\n")

    agent4 = MoriartyAgentLoop(max_tests=3)
    result4 = agent4.run(
        original_source=VULN_SOURCE,
        patched_source=PATCH_SOURCE,
        execute_submitted_source=True,
        report_path="reports/demo_source_execution_report.json",
    )

    print(f"\nFinal Verdict: [{result4.verdict.value}]")
    print(f"Final Action:  [{result4.final_action}]")
    print(f"Target Type:   [{result4.target_type}]")
    print(f"Provenance:    [{result4.target_provenance}] (SubmittedSourceExecuted={result4.submitted_source_executed})")
    print(f"Summary: {result4.verdict_summary}")

    print_header("Demonstration Complete")
    print("All scenarios executed cleanly.")
    print("Generated Reports:")
    print(" - reports/demo_verified_report.json         (VERIFIED - Local App)")
    print(" - reports/demo_rejected_report.json         (REJECTED - Incomplete Patch)")
    print(" - reports/demo_inconclusive_report.json     (INCONCLUSIVE - Fixture Honesty)")
    print(" - reports/demo_source_execution_report.json (VERIFIED - Submitted Source Execution)")


if __name__ == "__main__":
    run_demo()
