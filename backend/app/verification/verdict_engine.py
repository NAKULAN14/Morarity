from app.models.schemas import Evidence, Verdict


class VerdictEngine:
    """
    Determines a verification verdict from collected static and dynamic evidence.

    Preserves the strict three-outcome model with independent evidence validation:
    - VERIFIED: Validated empirical evidence from dynamic testing demonstrating
      baseline exploitability, patch neutralization, functionality preservation,
      and verified source/runtime correspondence.
    - REJECTED: Actual evidence demonstrates the vulnerability remains
      exploitable in the patched target.
    - INCONCLUSIVE: Evidence is insufficient, source/runtime mismatch, only static/fixtures
      are available, analysis is unsupported, or execution errored.
    """

    EXPLICIT_SCOPE = (
        "Verification scope: targeted local SQLite query construction path. "
        "Does not claim application-wide absence of other vulnerabilities."
    )

    ALLOWED_TARGET_TYPES = {
        "SUBMITTED_SOURCE_EXECUTION",
        "REAL_LOCAL_APPLICATION",
    }

    ALLOWED_TARGET_PROVENANCES = {
        "RESTRICTED_SOURCE_ENV",
        "REGISTERED_SCENARIO_MATCH",
    }

    def decide(
        self,
        evidence: list[Evidence],
    ) -> tuple[Verdict, str]:
        if not evidence:
            return (
                Verdict.INCONCLUSIVE,
                "No evidence was collected. The patch cannot be verified.",
            )

        # 1. Check for unsupported static analysis
        for item in evidence:
            if item.category == "STATIC_ANALYSIS":
                status = item.observed.get("status") if isinstance(item.observed, dict) else None
                if status == "ANALYSIS_UNSUPPORTED":
                    return (
                        Verdict.INCONCLUSIVE,
                        (
                            "Source code analysis was unsupported. Moriarty preserves "
                            "uncertainty and cannot establish a verification verdict."
                        ),
                    )

        # 2. Check source/runtime provenance and correspondence
        # Target provenance mismatch cannot produce a verdict about the submitted patch.
        # Even if a mismatched target demonstrates exploitability, it is INCONCLUSIVE for the submitted patch.
        for item in evidence:
            obs = item.observed if isinstance(item.observed, dict) else {}
            if item.category == "REAL_APPLICATION_VERIFICATION":
                if obs.get("source_runtime_match") is False:
                    return (
                        Verdict.INCONCLUSIVE,
                        (
                            "Source-to-runtime correspondence (target provenance) could not be established. "
                            "The executed target does not match the submitted patched source."
                        ),
                    )

        # 3. Check for direct evidence of vulnerability remaining present (REJECTED)
        # Direct evidence strictly requires:
        # - Target provenance corresponds to submitted patch (source_runtime_match is True)
        # - Baseline exploitability is proven (baseline_exploitable is True)
        # - Patched target fails to block the payload (patch_blocks_payload is False)
        # Generic outcome == "FAIL" is NOT classified as proof of exploitability.
        for item in evidence:
            obs = item.observed if isinstance(item.observed, dict) else {}
            if item.category == "REAL_APPLICATION_VERIFICATION":
                patch_blocks = obs.get("patch_blocks_payload")
                baseline_exploitable = obs.get("baseline_exploitable")
                source_match = obs.get("source_runtime_match")

                if (
                    source_match is True
                    and patch_blocks is False
                    and baseline_exploitable is True
                ):
                    return (
                        Verdict.REJECTED,
                        (
                            "Evidence demonstrates that the vulnerability remains exploitable in "
                            "the patched application. Test payloads altered SQL query logic or bypassed "
                            "insufficient query sanitization."
                        ),
                    )

        # 4. Check for runtime execution errors (without independent exploit evidence)
        for item in evidence:
            obs = item.observed if isinstance(item.observed, dict) else {}
            if obs.get("outcome") == "ERROR" or obs.get("error"):
                return (
                    Verdict.INCONCLUSIVE,
                    (
                        "Test execution encountered errors. "
                        "The evidence is insufficient to verify the patch."
                    ),
                )

        # 5. Filter for real application verification evidence
        real_app_evidence = [
            item for item in evidence
            if item.category == "REAL_APPLICATION_VERIFICATION"
        ]

        # If NO real application verification was performed, controlled demonstration
        # or static analysis ALONE can NEVER produce a VERIFIED verdict.
        if not real_app_evidence:
            return (
                Verdict.INCONCLUSIVE,
                (
                    "The controlled demonstration completed, but it did not execute the "
                    "submitted application. Real application dynamic verification is required "
                    "to verify the patch."
                ),
            )

        # 6. Check baseline exploitability and functionality preservation
        for item in real_app_evidence:
            obs = item.observed if isinstance(item.observed, dict) else {}
            if obs.get("baseline_exploitable") is False:
                return (
                    Verdict.INCONCLUSIVE,
                    (
                        "Baseline exploitability was not established for the test payloads; "
                        "evidence is insufficient to verify differential patch security."
                    ),
                )
            if obs.get("functionality_intact") is False:
                return (
                    Verdict.INCONCLUSIVE,
                    (
                        "Application functionality verification failed or required functionality "
                        "invariants were not satisfied."
                    ),
                )

        # 7. Strict validation of real application evidence
        # Do not trust supports_verification=True alone. Independently validate every required field.
        valid_supporting_items: list[Evidence] = []
        for item in real_app_evidence:
            if self._validate_verification_evidence(item):
                valid_supporting_items.append(item)

        # For VERIFIED:
        # All real items must be rigorously validated supporting evidence
        if valid_supporting_items and len(valid_supporting_items) == len(real_app_evidence):
            return (
                Verdict.VERIFIED,
                (
                    f"Controlled dynamic verification demonstrated that SQL injection payloads "
                    f"were blocked, parameters were safely separated, and application query "
                    f"functionality was preserved. {self.EXPLICIT_SCOPE}"
                ),
            )

        return (
            Verdict.INCONCLUSIVE,
            "The collected evidence is insufficient or contradictory, preventing a conclusive verdict.",
        )

    @classmethod
    def _validate_verification_evidence(cls, item: Evidence) -> bool:
        """
        Independently validate that an evidence item satisfies all required
        criteria to contribute to a VERIFIED verdict.
        """
        if item.category != "REAL_APPLICATION_VERIFICATION":
            return False
        if not item.supports_verification:
            return False

        obs = item.observed if isinstance(item.observed, dict) else {}

        # 1. Target type and provenance validation
        if obs.get("submitted_source_executed") is not True:
            return False
        if obs.get("target_type") not in cls.ALLOWED_TARGET_TYPES:
            return False
        if obs.get("target_provenance") not in cls.ALLOWED_TARGET_PROVENANCES:
            return False
        if obs.get("source_runtime_match") is not True:
            return False

        # 2. Meaningful verification scope validation
        scope = obs.get("verification_scope")
        if not isinstance(scope, str) or not scope.strip():
            return False
        if "demonstration fixture only" in scope.lower():
            return False

        # 3. Dynamic test results validation
        if obs.get("outcome") != "PASS" or obs.get("passed") is not True:
            return False
        if obs.get("baseline_exploitable") is not True:
            return False
        if obs.get("patch_blocks_payload") is not True:
            return False
        if obs.get("functionality_intact") is not True:
            return False
        if obs.get("error") is not None:
            return False

        return True
