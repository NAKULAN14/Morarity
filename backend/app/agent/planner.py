from dataclasses import dataclass
from typing import Any, Literal, Optional

from app.execution.differential_runner import DifferentialTestResult


PatchStatus = Literal[
    "ANALYSIS_UNSUPPORTED",
    "BASELINE_NOT_DETECTED",
    "VULNERABILITY_REMAINS",
    "PATCH_PATTERN_IMPROVED",
    "INCONCLUSIVE",
]


@dataclass
class PlanDecision:
    action: str
    reason: str
    next_payload: str | None = None
    strategy: str | None = None
    evidence_used: list[str] | None = None
    expected_learning: str | None = None
    stopping_reason: str | None = None


class AgentPlanner:
    """
    Observation-based and finding-aware planner for Moriarty.

    The planner uses AST analyzer findings (SQLI_UNSAFE_QUERY,
    SQLI_PARAMETERIZED_QUERY, SQLI_STATIC_QUERY, SQLI_UNKNOWN_QUERY)
    and static patch comparison results to select an appropriate
    verification strategy, challenge hypotheses, and adapt based on
    runtime observations.
    """

    def __init__(self, max_tests: int = 3) -> None:
        self.max_tests = max_tests

        self.boolean_strategies = [
            {
                "name": "BOOLEAN_OR",
                "payload": "' OR '1'='1",
                "expected": "Verify if boolean tautology alters query logic and leaks records.",
            },
            {
                "name": "BOOLEAN_COMMENT",
                "payload": "' OR 1=1 --",
                "expected": "Verify if SQL comment delimiter truncates query syntax.",
            },
            {
                "name": "BOOLEAN_ADMIN",
                "payload": "admin' OR '1'='1' --",
                "expected": "Verify if targeted user clause combined with comment bypasses authentication.",
            },
        ]

        self.fallback_strategies = [
            {
                "name": "BOOLEAN_TRUE",
                "payload": "' OR 1=1 --",
                "expected": "Test baseline sensitivity to standard SQL boolean tautology.",
            },
            {
                "name": "BOOLEAN_FALSE",
                "payload": "' AND 1=2 --",
                "expected": "Test baseline response to false condition to establish baseline differential.",
            },
        ]

    def plan(
        self,
        results: list[Any],
        patch_status: PatchStatus | None = None,
        original_rule_ids: list[str] | None = None,
        patched_rule_ids: list[str] | None = None,
    ) -> PlanDecision:
        """
        Produce next action and reasoning based on findings and test observations.
        """
        orig_rules = set(original_rule_ids or [])
        patch_rules = set(patched_rule_ids or [])
        evidence_used: list[str] = []

        if patch_status:
            evidence_used.append(f"patch_status:{patch_status}")
        if orig_rules:
            evidence_used.extend([f"orig:{r}" for r in orig_rules])
        if patch_rules:
            evidence_used.extend([f"patch:{r}" for r in patch_rules])

        # 1. Stop if source analysis was unsupported.
        if patch_status == "ANALYSIS_UNSUPPORTED":
            return PlanDecision(
                action="STOP_INCONCLUSIVE",
                reason=(
                    "Static analysis was unsupported because source code could not be parsed "
                    "or analyzed. Moriarty preserves uncertainty and avoids unsupported claims."
                ),
                evidence_used=evidence_used,
                expected_learning="None. Unparseable source prevents reliable verification planning.",
                stopping_reason="UNSUPPORTED_ANALYSIS",
            )

        # 2. Stop if patched query cannot be resolved (SQLI_UNKNOWN_QUERY)
        # and no recognized safe execution pattern is found.
        if "SQLI_UNKNOWN_QUERY" in patch_rules and not (patch_rules & {"SQLI_PARAMETERIZED_QUERY", "SQLI_STATIC_QUERY"}):
            return PlanDecision(
                action="STOP_INCONCLUSIVE",
                reason=(
                    "Triggered by finding SQLI_UNKNOWN_QUERY in patched source. "
                    "The SQL query structure could not be confidently classified. "
                    "Moriarty preserves uncertainty rather than claiming the vulnerability is fixed."
                ),
                evidence_used=evidence_used,
                expected_learning="Unknown SQL structure requires manual investigation or specialized analyzer.",
                stopping_reason="UNKNOWN_QUERY_STRUCTURE",
            )

        # 3. Check runtime observations for target provenance mismatch.
        for result in results:
            if getattr(result, "source_runtime_match", True) is False:
                return PlanDecision(
                    action="STOP_INCONCLUSIVE",
                    reason=(
                        "Runtime target provenance mismatch: executed application target "
                        "does not correspond to the submitted source code. "
                        "Moriarty preserves uncertainty and cannot evaluate the patch."
                    ),
                    evidence_used=evidence_used + ["provenance_mismatch"],
                    expected_learning="Source-to-runtime correspondence must be established.",
                    stopping_reason="TARGET_PROVENANCE_MISMATCH",
                )

        # 4. Check runtime observations for errors.
        for result in results:
            if getattr(result, "error", None) or getattr(result, "outcome", None) == "ERROR":
                err_msg = str(getattr(result, "error", "runtime_error"))
                return PlanDecision(
                    action="STOP_FOR_INVESTIGATION",
                    reason=(
                        "A test encountered an execution error. "
                        "The agent must investigate before continuing."
                    ),
                    evidence_used=evidence_used + [f"error:{err_msg}"],
                    expected_learning="Diagnose runtime failure before resuming testing.",
                    stopping_reason="RUNTIME_ERROR",
                )

        # 5. Check runtime observations for direct exploit evidence (REJECTED).
        # A generic failed test must NOT automatically mean STOP_REJECTED.
        # Only direct evidence of vulnerability remaining present: baseline was exploitable,
        # and the patch failed to block the payload.
        for result in results:
            patch_blocks = getattr(result, "patch_blocks_payload", None)
            baseline_exploitable = getattr(result, "baseline_exploitable", None)
            if patch_blocks is False and baseline_exploitable is True:
                return PlanDecision(
                    action="STOP_REJECTED",
                    reason=(
                        "The test payload was not safely blocked by the patched implementation, "
                        "while baseline exploitability was confirmed. "
                        "The agent is stopping verification because the vulnerability remains exploitable."
                    ),
                    evidence_used=evidence_used + ["direct_exploit_observation"],
                    expected_learning="Identify why the patch remains susceptible to SQL injection.",
                    stopping_reason="VULNERABILITY_REMAINS_EXPLOITABLE",
                )

        # 6. Check runtime observations for functionality regression.
        for result in results:
            if getattr(result, "functionality_intact", None) is False:
                return PlanDecision(
                    action="STOP_INCONCLUSIVE",
                    reason=(
                        "Application functionality verification failed. "
                        "The patch broke benign application behavior or required functionality invariants."
                    ),
                    evidence_used=evidence_used + ["functionality_invariant_violated"],
                    expected_learning="Fix must preserve application functionality without regressions.",
                    stopping_reason="FUNCTIONALITY_INVARIANT_VIOLATED",
                )

        # 5. Check if testing budget has been reached.
        if len(results) >= self.max_tests:
            # Check if collected results constitute sufficient empirical evidence for verification
            has_real_evidence = any(
                getattr(r, "target_type", "") in {"SUBMITTED_SOURCE_EXECUTION", "REAL_LOCAL_APPLICATION"}
                for r in results
            )
            all_passed = all(
                getattr(r, "passed", False)
                and getattr(r, "patch_blocks_payload", False)
                and getattr(r, "baseline_exploitable", False)
                and getattr(r, "functionality_intact", False)
                for r in results
            )

            if has_real_evidence and all_passed and len(results) > 0:
                return PlanDecision(
                    action="STOP_VERIFIED",
                    reason=(
                        f"Testing budget completed ({len(results)}/{self.max_tests} tests). "
                        "All controlled verification tests against the local target succeeded with "
                        "baseline exploitability proven, payload blocked, and functionality preserved."
                    ),
                    evidence_used=evidence_used + [f"sufficient_real_evidence:{len(results)}"],
                    expected_learning="Verification requirements satisfied across all planned strategies.",
                    stopping_reason="VERIFICATION_REQUIREMENTS_SATISFIED",
                )
            else:
                return PlanDecision(
                    action="STOP_INCONCLUSIVE",
                    reason=(
                        "The testing budget has been reached. "
                        "The available evidence is not sufficient to verify the submitted patch."
                    ),
                    evidence_used=evidence_used + [f"budget_reached:{len(results)}/{self.max_tests}"],
                    expected_learning="All budgeted test payloads executed.",
                    stopping_reason="TEST_BUDGET_EXHAUSTED_WITHOUT_SUFFICIENT_EVIDENCE",
                )

        # 6. Formulate finding-aware strategy context.
        if "SQLI_UNSAFE_QUERY" in patch_rules or patch_status == "VULNERABILITY_REMAINS":
            patch_context = (
                "Triggered by finding SQLI_UNSAFE_QUERY in patched source: "
                "unsafe SQL construction pattern remains detected. "
                "Prioritizing investigation of the potentially unsafe query construction."
            )
            strategy_expectation = "Determine if dynamically constructed SQL query in patch is exploitable at runtime."

        elif "SQLI_PARAMETERIZED_QUERY" in patch_rules or patch_status == "PATCH_PATTERN_IMPROVED":
            patch_context = (
                "Triggered by finding SQLI_PARAMETERIZED_QUERY in patched source: "
                "patched code appears to use a safer query construction pattern. "
                "This finding indicates structural improvement but does not prove runtime security. "
                "Planning controlled verification actions to challenge the parameterized implementation."
            )
            strategy_expectation = "Verify that SQL injection payloads are strictly handled as data parameters."

        elif "SQLI_STATIC_QUERY" in patch_rules:
            patch_context = (
                "Triggered by finding SQLI_STATIC_QUERY in patched source: "
                "query appears statically constructed. "
                "Avoid blindly treating every SQL string as exploitable."
            )
            strategy_expectation = "Confirm that user input cannot alter static SQL structure."

        elif patch_status == "BASELINE_NOT_DETECTED":
            patch_context = (
                "The original source did not contain a recognized unsafe SQL pattern. "
                "Patch improvement cannot be established from this comparison."
            )
            strategy_expectation = "Probe whether baseline query exhibits unexpected exploitability."

        elif patch_status == "INCONCLUSIVE":
            patch_context = (
                "Static comparison is inconclusive. "
                "The agent will preserve uncertainty and proceed cautiously with controlled verification."
            )
            strategy_expectation = "Gather empirical runtime evidence to resolve static ambiguity."

        else:
            patch_context = "No static patch-comparison finding context was supplied."
            strategy_expectation = "Execute baseline differential verification test."

        # 7. First test: select starting strategy.
        if not results:
            next_strategy = self.boolean_strategies[0]
            return PlanDecision(
                action="RUN_TEST",
                reason=(
                    f"No tests have been executed yet. {patch_context} "
                    "The agent is starting with a boolean-based test."
                ),
                next_payload=next_strategy["payload"],
                strategy=next_strategy["name"],
                evidence_used=evidence_used,
                expected_learning=next_strategy["expected"],
            )

        previous = results[-1]
        baseline_exploitable = getattr(previous, "baseline_exploitable", True)
        patch_blocks = getattr(previous, "patch_blocks_payload", True)

        # 8. Adaptive progression: If baseline was exploitable and patch blocked it,
        # escalate to the next distinct challenge.
        if baseline_exploitable and patch_blocks:
            used_payloads = {
                getattr(r, "payload", None) for r in results
            }

            for strategy in self.boolean_strategies:
                if strategy["payload"] not in used_payloads:
                    return PlanDecision(
                        action="RUN_TEST",
                        reason=(
                            f"{patch_context} "
                            "The previous payload exploited the baseline but was blocked "
                            "by the patched implementation. The agent is trying another "
                            "boolean-based strategy to attempt to disprove the fix."
                        ),
                        next_payload=strategy["payload"],
                        strategy=strategy["name"],
                        evidence_used=evidence_used + [f"prev_passed:{strategy['name']}"],
                        expected_learning=strategy["expected"],
                    )

        # 9. Fallback progression: If baseline was not exploitable, probe baseline with alternatives.
        if not baseline_exploitable:
            used_payloads = {
                getattr(r, "payload", None) for r in results
            }

            for strategy in self.fallback_strategies:
                if strategy["payload"] not in used_payloads:
                    return PlanDecision(
                        action="RUN_TEST",
                        reason=(
                            f"{patch_context} "
                            "The previous payload did not demonstrate baseline exploitability. "
                            "The agent is trying an alternative boolean strategy to establish baseline sensitivity."
                        ),
                        next_payload=strategy["payload"],
                        strategy=strategy["name"],
                        evidence_used=evidence_used + ["baseline_not_exploitable"],
                        expected_learning=strategy["expected"],
                    )

        return PlanDecision(
            action="STOP_INCONCLUSIVE",
            reason=(
                f"{patch_context} "
                "No unused strategy is available for the observed behavior. More testing is required."
            ),
            evidence_used=evidence_used,
            expected_learning="Testing strategies exhausted.",
            stopping_reason="STRATEGIES_EXHAUSTED",
        )
