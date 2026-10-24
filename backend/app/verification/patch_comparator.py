
from dataclasses import dataclass
from typing import Literal

from app.analyzer.ast_analyzer import SQLInjectionAnalyzer
from app.models.schemas import AnalysisResult


PatchComparisonStatus = Literal[
    "ANALYSIS_UNSUPPORTED",
    "BASELINE_NOT_DETECTED",
    "VULNERABILITY_REMAINS",
    "PATCH_PATTERN_IMPROVED",
    "INCONCLUSIVE",
]


@dataclass
class PatchComparisonResult:
    status: PatchComparisonStatus
    summary: str
    original_analysis: AnalysisResult
    patched_analysis: AnalysisResult
    original_rule_ids: list[str]
    patched_rule_ids: list[str]
    static_improvement_detected: bool
    dynamic_verification_performed: bool = False


class PatchComparator:
    """
    Compare original and patched Python source using the existing
    SQLInjectionAnalyzer.

    This is a static comparison only. It does not execute either source
    file and does not establish runtime security.
    """

    UNSAFE_RULE = "SQLI_UNSAFE_QUERY"
    UNKNOWN_RULE = "SQLI_UNKNOWN_QUERY"

    RECOGNIZED_SAFE_RULES = {
        "SQLI_PARAMETERIZED_QUERY",
        "SQLI_STATIC_QUERY",
    }

    def __init__(
        self,
        analyzer: SQLInjectionAnalyzer | None = None,
    ) -> None:
        self.analyzer = analyzer or SQLInjectionAnalyzer()

    def compare(
        self,
        original_source: str,
        patched_source: str,
    ) -> PatchComparisonResult:
        original_analysis = self.analyzer.analyze(original_source)
        patched_analysis = self.analyzer.analyze(patched_source)

        original_rule_ids = [
            finding.rule_id
            for finding in original_analysis.findings
        ]
        patched_rule_ids = [
            finding.rule_id
            for finding in patched_analysis.findings
        ]

        def result(
            status: PatchComparisonStatus,
            summary: str,
            improved: bool = False,
        ) -> PatchComparisonResult:
            return PatchComparisonResult(
                status=status,
                summary=summary,
                original_analysis=original_analysis,
                patched_analysis=patched_analysis,
                original_rule_ids=original_rule_ids,
                patched_rule_ids=patched_rule_ids,
                static_improvement_detected=improved,
            )

        # Both versions must be parseable and supported.
        if not original_analysis.supported or not patched_analysis.supported:
            return result(
                "ANALYSIS_UNSUPPORTED",
                (
                    "At least one source version could not be analyzed. "
                    "The patch comparison is inconclusive."
                ),
            )

        # We need a detected unsafe pattern in the baseline to compare
        # against. Otherwise, the comparator cannot establish improvement.
        if self.UNSAFE_RULE not in original_rule_ids:
            return result(
                "BASELINE_NOT_DETECTED",
                (
                    "The original source does not contain a recognized "
                    "unsafe SQL construction. The comparator cannot "
                    "establish that this patch fixes a detected issue."
                ),
            )

        # If the unsafe pattern still exists in the patched source,
        # report that the static concern remains.
        if self.UNSAFE_RULE in patched_rule_ids:
            return result(
                "VULNERABILITY_REMAINS",
                (
                    "The patched source still contains a recognized "
                    "unsafe SQL construction."
                ),
            )

        # Unknown SQL structures prevent a confident static comparison.
        if self.UNKNOWN_RULE in patched_rule_ids:
            return result(
                "INCONCLUSIVE",
                (
                    "The patched source no longer shows the original "
                    "recognized unsafe pattern, but it contains SQL "
                    "execution structures that could not be classified."
                ),
            )

        # Require at least one recognized SQL execution finding in the
        # patch. Removing the SQL call entirely is not proof of a fix.
        has_recognized_sql = any(
            rule_id in self.RECOGNIZED_SAFE_RULES
            for rule_id in patched_rule_ids
        )

        if not has_recognized_sql:
            return result(
                "INCONCLUSIVE",
                (
                    "The original unsafe pattern was not detected in the "
                    "patched source, but no recognized safe SQL execution "
                    "pattern was found to compare."
                ),
            )

        return result(
            "PATCH_PATTERN_IMPROVED",
            (
                "The recognized unsafe SQL construction in the original "
                "source is absent from the patched source, and the patch "
                "contains a recognized static or parameterized SQL pattern. "
                "This is a static improvement signal, not dynamic verification."
            ),
            improved=True,
        )


def compare_patch(
    original_source: str,
    patched_source: str,
) -> PatchComparisonResult:
    """Convenience function for comparing two source versions."""
    return PatchComparator().compare(
        original_source=original_source,
        patched_source=patched_source,
    )
