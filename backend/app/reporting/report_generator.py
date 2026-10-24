import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.models.schemas import VerificationResponse


class ReportGenerator:
    """
    Generates a structured, transparent JSON report from a verification response.

    Static analysis and controlled demonstration results are never
    treated as proof of runtime security.
    """

    DEFAULT_LIMITATIONS = [
        "Static source comparison does not establish runtime security.",
        "Controlled demonstration tests do not execute the submitted application.",
        "A VERIFIED verdict requires empirical evidence that directly supports the relevant security invariants.",
        "Verification scope is limited to the tested SQL query execution path.",
    ]

    def generate(
        self,
        response: VerificationResponse,
        output_path: str | Path | None = None,
        patch_comparison: Any | None = None,
        verification_scope: str | None = None,
        dynamic_verification_performed: bool | None = None,
        target_type: str | None = None,
        decision_trace: list[dict] | None = None,
    ) -> dict[str, Any]:
        patch_comparison_json = self._to_jsonable(patch_comparison)

        analysis_json = response.analysis.model_dump(mode="json")

        if isinstance(patch_comparison_json, dict):
            patched_analysis = patch_comparison_json.get("patched_analysis")

            if isinstance(patched_analysis, dict):
                analysis_json = patched_analysis

        scope = verification_scope or response.verification_scope or (
            "Targeted local SQLite user search query path"
            if dynamic_verification_performed or response.dynamic_verification_performed
            else "Simulated demonstration fixture only"
        )

        dynamic_performed = (
            dynamic_verification_performed
            if dynamic_verification_performed is not None
            else bool(response.dynamic_verification_performed)
        )

        app_target = target_type or response.target_type or (
            "REAL_LOCAL_APPLICATION" if dynamic_performed else "CONTROLLED_FIXTURE"
        )

        report = {
            "verification_id": response.verification_id,
            "verdict": response.verdict.value,
            "summary": response.summary,
            "verification_scope": scope,
            "dynamic_verification_performed": dynamic_performed,
            "target_type": app_target,
            "target_provenance": response.target_provenance,
            "submitted_source_executed": response.submitted_source_executed,
            "source_runtime_match": response.source_runtime_match,
            "final_action": response.final_action,
            "stopping_reason": response.stopping_reason,
            "analysis": analysis_json,
            "tests_executed": [
                test.model_dump(mode="json")
                for test in response.tests_executed
            ],
            "evidence": [
                item.model_dump(mode="json")
                for item in response.evidence
            ],
            "limitations": self._build_limitations(response),
            "patch_comparison": patch_comparison_json,
        }

        if decision_trace is not None:
            if "agent" not in report:
                report["agent"] = {}
            report["agent"]["decision_trace"] = decision_trace

        if output_path is not None:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with path.open("w", encoding="utf-8") as file:
                json.dump(
                    report,
                    file,
                    indent=4,
                    ensure_ascii=False,
                )

        return report

    def _build_limitations(
        self,
        response: VerificationResponse,
    ) -> list[str]:
        limitations = list(self.DEFAULT_LIMITATIONS)

        for limitation in response.limitations:
            if limitation not in limitations:
                limitations.append(limitation)

        return limitations

    @classmethod
    def _to_jsonable(cls, value: Any) -> Any:
        """
        Recursively convert nested objects into JSON-compatible values.
        """

        if isinstance(value, BaseModel):
            return cls._to_jsonable(value.model_dump())

        if isinstance(value, Enum):
            return value.value

        if is_dataclass(value) and not isinstance(value, type):
            return cls._to_jsonable(asdict(value))

        if isinstance(value, dict):
            return {
                str(key): cls._to_jsonable(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [cls._to_jsonable(item) for item in value]

        if value is None or isinstance(
            value,
            (str, int, float, bool),
        ):
            return value

        return str(value)
