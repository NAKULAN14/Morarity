import json
import os
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from app.models.schemas import (
    AnalysisResult,
    FindingSeverity,
    TestResult,
    Verdict,
    VerificationRequest,
    VerificationResponse,
)
from app.agent.controller import VerificationController
from app.agent.agent_loop import MoriartyAgentLoop
from app.scenarios.vulnerable import VulnerableUserApp, SOURCE_CODE as VULN_SOURCE
from app.scenarios.correct_patch import PatchedUserApp, SOURCE_CODE as PATCH_SOURCE
from app.scenarios.incomplete_patch import IncompletePatchUserApp, SOURCE_CODE as INCOMPLETE_SOURCE
from app.scenarios.regression_patch import RegressionUserApp, SOURCE_CODE as REGRESSION_SOURCE
from app.scenarios.unsupported_patch import SOURCE_CODE as UNSUPPORTED_SOURCE

router = APIRouter()
controller = VerificationController()

REPORTS_DIR = Path("reports")


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Moriarty",
        "version": "0.1.0",
        "engine": "Structural Security Patch Verification Agent",
    }


@router.get("/scenarios")
def get_scenarios():
    """Return built-in security patch verification scenarios for demonstration and testing."""
    return [
        {
            "id": "valid_parameterized",
            "name": "Scenario 1: Valid Parameterized Query Patch",
            "expected_verdict": "VERIFIED",
            "vulnerability_type": "SQL_INJECTION",
            "badge_color": "green",
            "description": (
                "Replaces vulnerable string concatenation with SQLite parameter placeholders (?). "
                "The agent challenges the implementation with multiple payloads, establishes baseline exploitability, "
                "confirms zero unauthorized record leakage, and proves benign functionality preservation."
            ),
            "original_source": VULN_SOURCE,
            "patched_source": PATCH_SOURCE,
            "default_mode": "isolated_execution",
        },
        {
            "id": "incomplete_sanitization",
            "name": "Scenario 2: Incomplete Sanitization Patch",
            "expected_verdict": "REJECTED",
            "vulnerability_type": "SQL_INJECTION",
            "badge_color": "red",
            "description": (
                "Attempts to sanitize user input by stripping '--' comment characters, but leaves single quotes unescaped. "
                "The agent executes controlled boolean-or injection (' OR '1'='1) and observes that unauthorized records "
                "continue to leak. Disproves the fix and rejects the patch."
            ),
            "original_source": VULN_SOURCE,
            "patched_source": INCOMPLETE_SOURCE,
            "default_mode": "isolated_execution",
        },
        {
            "id": "functionality_regression",
            "name": "Scenario 3: Functionality Regression Patch",
            "expected_verdict": "INCONCLUSIVE",
            "vulnerability_type": "SQL_INJECTION",
            "badge_color": "amber",
            "description": (
                "Replaces the query with a hardcoded static lookup (WHERE id = 1). While SQL injection is neutralized, "
                "benign user lookups (e.g. searching for 'bob') fail. The agent refuses to verify a broken application and marks inconclusive."
            ),
            "original_source": VULN_SOURCE,
            "patched_source": REGRESSION_SOURCE,
            "default_mode": "isolated_execution",
        },
        {
            "id": "controlled_fixture_only",
            "name": "Scenario 4: Controlled Demonstration Fixture (Simulated)",
            "expected_verdict": "INCONCLUSIVE",
            "vulnerability_type": "SQL_INJECTION",
            "badge_color": "amber",
            "description": (
                "Simulated in-memory fixture tests pass, but submitted application source is not executed. "
                "Enforces verification honesty: Moriarty refuses false safety claims without real target execution."
            ),
            "original_source": VULN_SOURCE,
            "patched_source": PATCH_SOURCE,
            "default_mode": "fixture_only",
        },
        {
            "id": "unsupported_syntax",
            "name": "Scenario 5: Unsupported Python Syntax",
            "expected_verdict": "INCONCLUSIVE",
            "vulnerability_type": "SQL_INJECTION",
            "badge_color": "amber",
            "description": (
                "Submitted source contains invalid Python syntax preventing AST parsing. "
                "Moriarty preserves uncertainty instead of making unsupported security claims."
            ),
            "original_source": VULN_SOURCE,
            "patched_source": UNSUPPORTED_SOURCE,
            "default_mode": "isolated_execution",
        },
    ]


@router.post("/verify", response_model=VerificationResponse)
def verify_patch(request: VerificationRequest):
    try:
        # 1. Differential Agent Loop Verification (original + patched sources provided)
        if request.original_source and request.patched_source:
            agent = MoriartyAgentLoop(max_tests=request.max_tests or 3)

            run_id = str(uuid4())[:8]
            report_filename = f"reports/verify_run_{run_id}.json"

            is_fixture_only = (request.target_type == "CONTROLLED_FIXTURE") or (request.execute_submitted_source is False)

            if is_fixture_only:
                result = agent.run(
                    original_source=request.original_source,
                    patched_source=request.patched_source,
                    vulnerable_app=None,
                    patched_app=None,
                    execute_submitted_source=False,
                    report_path=report_filename,
                )
            else:
                # Use registered scenario app if scenario ID provided, else isolated execution
                vuln_app = None
                patch_app = None
                execute_src = True

                if request.scenario == "valid_parameterized":
                    vuln_app = VulnerableUserApp()
                    patch_app = PatchedUserApp()
                    execute_src = False
                elif request.scenario == "incomplete_sanitization":
                    vuln_app = VulnerableUserApp()
                    patch_app = IncompletePatchUserApp()
                    execute_src = False
                elif request.scenario == "functionality_regression":
                    vuln_app = VulnerableUserApp()
                    patch_app = RegressionUserApp()
                    execute_src = False

                result = agent.run(
                    original_source=request.original_source,
                    patched_source=request.patched_source,
                    vulnerable_app=vuln_app,
                    patched_app=patch_app,
                    execute_submitted_source=execute_src,
                    report_path=report_filename,
                )

            if result.verification_response:
                res = result.verification_response
                res.scenario_id = request.scenario
                return res

            # Fallback construct if verification_response not set
            return VerificationResponse(
                verification_id=run_id,
                verdict=result.verdict,
                summary=result.verdict_summary,
                analysis=AnalysisResult(
                    supported=True,
                    vulnerability_type="SQL_INJECTION",
                    findings=[],
                    security_invariants=[],
                    summary=result.verdict_summary,
                ),
                tests_executed=[],
                evidence=result.evidence,
                limitations=[],
                target_type=result.target_type,
                target_provenance=result.target_provenance,
                submitted_source_executed=result.submitted_source_executed,
                source_runtime_match=result.source_runtime_match,
                final_action=result.final_action,
                stopping_reason=result.stopping_reason,
                decision_trace=result.decision_trace,
                scenario_id=request.scenario,
            )

        # 2. Legacy / Single-source analysis (backwards compatible with test_api.py)
        if request.source_code:
            return controller.verify(request)

        raise HTTPException(
            status_code=400,
            detail="Either 'source_code' or both 'original_source' and 'patched_source' must be provided.",
        )

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/reports")
def get_reports():
    """List all persisted verification reports on disk with metadata."""
    if not REPORTS_DIR.exists():
        return []

    reports = []
    for p in REPORTS_DIR.glob("*.json"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)

            stat = p.stat()
            reports.append({
                "filename": p.name,
                "verification_id": data.get("verification_id", p.stem),
                "verdict": data.get("verdict", "INCONCLUSIVE"),
                "summary": data.get("verdict_summary") or data.get("summary", ""),
                "target_type": data.get("target_type", "UNKNOWN"),
                "target_provenance": data.get("target_provenance", "UNKNOWN"),
                "timestamp": data.get("timestamp") or stat.st_mtime,
                "tests_run": len(data.get("tests", [])),
                "findings_count": len(data.get("analysis", {}).get("findings", [])),
                "final_action": data.get("agent", {}).get("final_action", ""),
                "stopping_reason": data.get("agent", {}).get("stopping_reason", ""),
            })
        except Exception:
            continue

    # Sort newest first by timestamp / mtime
    reports.sort(key=lambda r: str(r.get("timestamp", "")), reverse=True)
    return reports


@router.get("/reports/{filename}")
def get_report_detail(filename: str):
    """Retrieve full verification report details for a specific file."""
    # Prevent path traversal
    safe_name = Path(filename).name
    report_file = REPORTS_DIR / safe_name
    if not report_file.exists():
        raise HTTPException(status_code=404, detail=f"Report '{safe_name}' not found.")

    try:
        with open(report_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error reading report: {exc}")


@router.get("/stats")
def get_verification_stats():
    """Aggregate actual verification statistics from reports on disk."""
    reports = get_reports()
    total = len(reports)
    verified = sum(1 for r in reports if r.get("verdict") == "VERIFIED")
    rejected = sum(1 for r in reports if r.get("verdict") == "REJECTED")
    inconclusive = sum(1 for r in reports if r.get("verdict") == "INCONCLUSIVE")

    return {
        "total_verifications": total,
        "verified_count": verified,
        "rejected_count": rejected,
        "inconclusive_count": inconclusive,
        "verified_percentage": round((verified / total * 100), 1) if total > 0 else 0,
        "recent_verifications": reports[:6],
    }
