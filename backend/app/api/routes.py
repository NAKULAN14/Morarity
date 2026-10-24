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
    SQLAnalysisRequest,
    SQLAnalysisResponse,
    PatchGenerationRequest,
    PatchGenerationResponse,
    PatchRefineRequest,
    PatchRefineResponse,
    PlannerComparisonResult,
    ComprehensiveBenchmarkResponse,
    ContinuousEvaluationRequest,
    ContinuousEvaluationResponse,
    LabVerificationRequest,
    CatalogResponse,
    CatalogCategorySchema,
    CatalogTestCaseSchema,
)
from app.agent.controller import VerificationController
from app.agent.agent_loop import MoriartyAgentLoop
from app.agent.planner import AgentPlanner
from app.catalog.sql_catalog import get_catalog, get_categories
from app.patching.sql_analyzer import SQLVulnerabilityAnalyzer
from app.patching.generator import SQLPatchGenerator
from app.scenarios.vulnerable import VulnerableUserApp, SOURCE_CODE as VULN_SOURCE
from app.scenarios.correct_patch import PatchedUserApp, SOURCE_CODE as PATCH_SOURCE
from app.scenarios.incomplete_patch import IncompletePatchUserApp, SOURCE_CODE as INCOMPLETE_SOURCE
from app.scenarios.regression_patch import RegressionUserApp, SOURCE_CODE as REGRESSION_SOURCE
from app.scenarios.unsupported_patch import SOURCE_CODE as UNSUPPORTED_SOURCE

router = APIRouter()
controller = VerificationController()

REPORTS_DIR = Path("reports")


def resolve_budget(budget_preset: Optional[str], max_tests: Optional[int]) -> int:
    """Resolve configured test budget from preset or custom value."""
    if budget_preset == "quick":
        return 5
    elif budget_preset == "standard":
        return 15
    elif budget_preset == "thorough":
        return 30
    elif budget_preset == "custom":
        return max(1, min(max_tests or 5, 50))
    return max_tests or 5


@router.get("/catalog", response_model=CatalogResponse)
def get_catalog_endpoint():
    """Return the structured SQL injection test catalog across all 12 categories."""
    categories_raw = get_categories()
    categories_schema = [CatalogCategorySchema(**c) for c in categories_raw]
    tests_raw = get_catalog()
    tests_schema = [CatalogTestCaseSchema(**t.to_dict()) for t in tests_raw]

    total = len(tests_schema)
    exec_count = sum(1 for t in tests_schema if t.execution_support == "SUPPORTED")
    unsupp_count = total - exec_count

    return CatalogResponse(
        categories=categories_schema,
        total_tests=total,
        executable_tests=exec_count,
        unsupported_tests=unsupp_count,
        tests=tests_schema,
    )


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
            budget = resolve_budget(request.budget_preset, request.max_tests)
            agent = MoriartyAgentLoop(max_tests=budget)

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


# ============================================================================
# SQL Security Lab Endpoints
# ============================================================================

sql_analyzer_instance = SQLVulnerabilityAnalyzer()
patch_generator_instance = SQLPatchGenerator()


@router.post("/lab/analyze", response_model=SQLAnalysisResponse)
def analyze_sql_input(request: SQLAnalysisRequest):
    """
    Analyze raw SQL query or Python code for SQL injection vulnerabilities,
    extract parameters and security invariants.
    """
    try:
        res = sql_analyzer_instance.analyze(request.input_text, input_type=request.input_type or "auto")
        return SQLAnalysisResponse(**res)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(exc)}")


@router.post("/lab/generate-patch", response_model=PatchGenerationResponse)
def generate_sql_patch(request: PatchGenerationRequest):
    """
    Generate deterministic parameterized security patch with technical explanation,
    diff, and executable wrappers for verification.
    """
    try:
        res = patch_generator_instance.generate_patch(
            input_text=request.input_text,
            input_type=request.input_type or "auto",
            param_name=request.param_name,
        )
        return PatchGenerationResponse(**res)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Patch generation failed: {str(exc)}")


@router.post("/lab/verify-patch", response_model=VerificationResponse)
def verify_lab_patch(request: LabVerificationRequest):
    """
    Execute empirical differential verification of candidate patch against in-memory SQLite sandbox
    using MoriartyAgentLoop. Never assumes a generated patch is secure.
    """
    try:
        orig = request.original_source.strip()
        patch = request.candidate_patch.strip()

        # Check if source is Python or raw SQL
        is_orig_py = sql_analyzer_instance.is_python(orig)
        is_patch_py = sql_analyzer_instance.is_python(patch)

        # Synthesize runnable Python targets if raw SQL is provided
        if not is_orig_py:
            analysis = sql_analyzer_instance.analyze(orig)
            param = analysis["detected_parameters"][0] if analysis["detected_parameters"] else "username"
            table = analysis.get("detected_table") or "users"
            exec_orig = patch_generator_instance._synthesize_vulnerable_python(orig, param, table)
        else:
            exec_orig = orig

        if not is_patch_py:
            analysis_p = sql_analyzer_instance.analyze(patch)
            param_p = analysis_p["detected_parameters"][0] if analysis_p["detected_parameters"] else "username"
            exec_patch = patch_generator_instance._synthesize_patched_python(patch, param_p)
        else:
            exec_patch = patch

        run_id = str(uuid4())[:8]
        report_filename = f"reports/verify_lab_{run_id}.json"

        budget = resolve_budget(request.budget_preset, request.max_tests)
        agent = MoriartyAgentLoop(max_tests=budget)
        result = agent.run(
            original_source=exec_orig,
            patched_source=exec_patch,
            execute_submitted_source=True,
            report_path=report_filename,
        )

        if result.verification_response:
            return result.verification_response

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
            patch_comparison=result.patch_comparison.__dict__ if result.patch_comparison else None,
            coverage=result.coverage,
            original_ml_analysis=result.original_ml_analysis,
            patched_ml_analysis=result.patched_ml_analysis,
            llm_reasoning=result.llm_reasoning,
            evidence_graph=result.evidence_graph,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Lab verification failed: {str(exc)}")


@router.post("/lab/refine-patch", response_model=PatchRefineResponse)
def refine_sql_patch(request: PatchRefineRequest):
    """
    Execute bounded patch refinement loop (up to max_attempts):
    Re-analyzes patch candidates using both static AST and ML classifiers,
    detects incomplete sanitizers or residual vulnerabilities, and refines
    into clean parameterized code before dynamic verification.
    """
    try:
        res = patch_generator_instance.refine_patch_loop(
            original_source=request.original_source,
            current_patch=request.current_patch,
            max_attempts=request.max_attempts,
            param_name=request.param_name,
        )
        return PatchRefineResponse(**res)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Patch refinement failed: {str(exc)}")


@router.post("/lab/compare-planners", response_model=PlannerComparisonResult)
def compare_planners_endpoint(request: VerificationRequest):
    """
    Benchmark rule-based planner vs ML-guided planner on identical targets and test budgets.
    Tracks test count, bypass detection speed, execution duration, and category coverage.
    """
    try:
        scenario_id = request.scenario or "valid_parameterized"
        budget = resolve_budget(request.budget_preset, request.max_tests)

        if scenario_id == "incomplete_patch":
            vuln_app = VulnerableUserApp()
            patch_app = IncompletePatchUserApp()
            orig_src = vuln_app.source_code
            patch_src = patch_app.source_code
            name = "Incomplete Patch Sanitizer (Bypass Challenge)"
        else:
            vuln_app = VulnerableUserApp()
            patch_app = PatchedUserApp()
            orig_src = request.original_source or vuln_app.source_code
            patch_src = request.patched_source or patch_app.source_code
            name = "Valid Parameterized Query Patch"

        planner = AgentPlanner(max_tests=budget)
        comparison = planner.compare_planners(
            vulnerable_app=vuln_app,
            patched_app=patch_app,
            original_source=orig_src,
            patched_source=patch_src,
            scenario_id=scenario_id,
            scenario_name=name,
            budget=budget,
        )
        return comparison
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Planner comparison failed: {str(exc)}")


@router.get("/planner/benchmark", response_model=ComprehensiveBenchmarkResponse)
@router.post("/planner/benchmark", response_model=ComprehensiveBenchmarkResponse)
def run_comprehensive_planner_benchmark(budget: int = 5):
    """
    Execute comprehensive multi-mode benchmark evaluating Rule-based, ML-guided,
    LLM-assisted, and Combined verification planners across preset evaluation testbeds.
    """
    try:
        scenarios = get_scenarios()
        planner = AgentPlanner(max_tests=budget)
        return planner.benchmark_comprehensive(scenarios, budget=budget)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Benchmark execution failed: {str(exc)}")


@router.post("/lab/evaluate", response_model=ContinuousEvaluationResponse)
def continuous_evaluate(request: ContinuousEvaluationRequest):
    """
    Continuous evaluation endpoint for debounced real-time analysis,
    patch generation, and optional automated verification.
    """
    try:
        # 1. Analyze
        analysis_data = sql_analyzer_instance.analyze(request.source_code)
        analysis_resp = SQLAnalysisResponse(**analysis_data)

        # 2. Patch generation if needed
        generated_patch_resp = None
        current_patch = request.patch_code
        if not current_patch and analysis_resp.is_vulnerable:
            gen_data = patch_generator_instance.generate_patch(request.source_code)
            generated_patch_resp = PatchGenerationResponse(**gen_data)
            current_patch = generated_patch_resp.patched_code

        # 3. Auto-verify if requested and patch exists
        verif_resp = None
        status = "ANALYSIS_COMPLETE"

        if request.auto_verify and current_patch:
            budget = resolve_budget(request.budget_preset, request.max_tests)
            lab_req = LabVerificationRequest(
                original_source=request.source_code,
                candidate_patch=current_patch,
                source_revision=request.source_revision,
                patch_revision=request.patch_revision,
                max_tests=budget,
                budget_preset=request.budget_preset,
            )
            verif_resp = verify_lab_patch(lab_req)
            status = f"VERIFIED_{verif_resp.verdict.value}"
        elif analysis_resp.is_vulnerable:
            status = "VULNERABILITY_DETECTED"
        else:
            status = "NO_VULNERABILITY_DETECTED"

        coverage = verif_resp.coverage if verif_resp else None

        return ContinuousEvaluationResponse(
            source_revision=request.source_revision,
            patch_revision=request.patch_revision,
            is_stale=False,
            status=status,
            analysis=analysis_resp,
            generated_patch=generated_patch_resp,
            verification_result=verif_resp,
            coverage=coverage,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Continuous evaluation failed: {str(exc)}")

