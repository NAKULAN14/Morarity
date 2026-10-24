from app.models.schemas import Evidence, Verdict


class VerdictEngine:
    """
    Determines a verification verdict from collected evidence.

    The current evidence comes from a controlled SQLite
    demonstration, not execution of the submitted application.
    Therefore, it cannot independently establish that a patch
    is verified.
    """

    def decide(
        self,
        evidence: list[Evidence],
    ) -> tuple[Verdict, str]:
        if not evidence:
            return (
                Verdict.INCONCLUSIVE,
                "No evidence was collected. The patch cannot be verified.",
            )

        # A passing demonstration test is not proof that the
        # submitted application is secure.
        if any(
            item.category == "CONTROLLED_DEMONSTRATION"
            for item in evidence
        ):
            return (
                Verdict.INCONCLUSIVE,
                (
                    "The controlled demonstration completed, but it did "
                    "not execute the submitted application. More evidence "
                    "is required to verify the patch."
                ),
            )

        # Look for evidence that directly indicates a vulnerability
        # remains present.
        if any(
            item.observed.get("outcome") == "FAIL"
            and item.supports_verification is False
            for item in evidence
        ):
            return (
                Verdict.REJECTED,
                (
                    "Evidence indicates that the security property "
                    "may still be violated."
                ),
            )

        # Only evidence explicitly marked as supporting verification
        # can contribute to a VERIFIED verdict.
        if all(
            item.supports_verification
            for item in evidence
        ):
            return (
                Verdict.VERIFIED,
                (
                    "All collected evidence supports the security "
                    "invariants."
                ),
            )

        return (
            Verdict.INCONCLUSIVE,
            (
                "The collected evidence is insufficient to establish "
                "whether the patch is secure."
            ),
        )