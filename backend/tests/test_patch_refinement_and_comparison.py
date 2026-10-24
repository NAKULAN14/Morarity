"""
Tests for Patch Refinement Loop, ML-Guided Planning, and Planner Benchmarking.

Validates:
1. Bounded patch refinement loop (max attempts, AST re-analysis, ML re-analysis).
2. Flawed patch sanitizer refinement into clean parameterization.
3. Patch candidate history with diffs and before/after ML risk scores.
4. ML-guided explainable planner decisions citing ML risk and features.
5. Planner comparison benchmark (rule-based vs ML-guided).
6. API routes for patch refinement and planner benchmarking.
"""

from app.agent.agent_loop import MoriartyAgentLoop
from app.agent.planner import AgentPlanner
from app.api.routes import compare_planners_endpoint, refine_sql_patch
from app.models.schemas import (
    PatchRefineRequest,
    VerificationRequest,
)
from app.patching.generator import SQLPatchGenerator
from app.scenarios.correct_patch import PatchedUserApp
from app.scenarios.incomplete_patch import IncompletePatchUserApp
from app.scenarios.vulnerable import VulnerableUserApp


FLAWED_SANITIZER_CODE = """def get_user_by_username(cursor, username: str):
    sanitized = username.replace('--', '')
    query = "SELECT id, username, role, email FROM users WHERE username = '" + sanitized + "'"
    cursor.execute(query)
    return cursor.fetchall()"""

VULNERABLE_SOURCE = """def get_user_by_username(cursor, username: str):
    query = "SELECT id, username, role, email FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()"""


def test_patch_refinement_improves_flawed_sanitizer():
    """Verify refinement loop detects incomplete sanitization and refines into parameterization."""
    generator = SQLPatchGenerator()
    res = generator.refine_patch_loop(
        original_source=VULNERABLE_SOURCE,
        current_patch=FLAWED_SANITIZER_CODE,
        max_attempts=3,
        param_name="username",
    )

    assert res["is_fully_refined"] is True
    assert res["attempts_made"] <= 3
    assert len(res["candidates"]) >= 1
    assert "?" in res["final_patch"]

    # Original risk should be higher than final risk
    assert res["original_ml_analysis"]["risk_score"] > res["final_ml_analysis"]["risk_score"]
    assert res["final_ml_analysis"]["risk_score"] <= 0.25


def test_patch_refinement_respects_max_attempts():
    """Refinement loop strictly halts at max_attempts."""
    generator = SQLPatchGenerator()
    res = generator.refine_patch_loop(
        original_source=VULNERABLE_SOURCE,
        current_patch=FLAWED_SANITIZER_CODE,
        max_attempts=1,
    )
    assert res["attempts_made"] == 1
    assert len(res["candidates"]) == 1


def test_patch_refinement_preserves_candidate_history_and_diffs():
    """Candidate history retains diffs and explanations without discarding attempts."""
    generator = SQLPatchGenerator()
    res = generator.refine_patch_loop(
        original_source=VULNERABLE_SOURCE,
        current_patch=FLAWED_SANITIZER_CODE,
        max_attempts=2,
    )

    for cand in res["candidates"]:
        assert "attempt" in cand
        assert "patch_code" in cand
        assert "diff_lines" in cand
        assert len(cand["diff_lines"]) > 0
        assert "ml_risk_score" in cand
        assert "explanation" in cand


def test_ml_guided_planning_explanation():
    """Planner explains initial decision using ML risk score and detected features."""
    planner = AgentPlanner(max_tests=5)
    ml_analysis = {
        "model_status": "trained",
        "predicted_class": "potential_sql_injection",
        "risk_score": 0.88,
        "risk_level": "CRITICAL",
        "detected_features": ["string_concatenation_in_query"],
        "recommended_test_categories": ["Quote and delimiter handling"],
    }

    decision = planner.plan(
        results=[],
        ml_analysis=ml_analysis,
        mode="ml_guided",
    )

    assert decision.action == "RUN_TEST"
    assert "ML analyzer assigned a high risk score" in decision.reason
    assert "0.88" in decision.reason
    assert "quote-handling challenge" in decision.reason


def test_compare_planners_benchmark():
    """Planner comparison evaluates rule-based vs ML-guided planners on identical scenario."""
    vuln_app = VulnerableUserApp()
    patch_app = PatchedUserApp()

    try:
        planner = AgentPlanner(max_tests=5)
        benchmark = planner.compare_planners(
            vulnerable_app=vuln_app,
            patched_app=patch_app,
            original_source=vuln_app.source_code,
            patched_source=patch_app.source_code,
            scenario_id="valid_parameterized",
            scenario_name="Valid Parameterized Query Patch",
            budget=5,
        )

        assert benchmark.scenario_id == "valid_parameterized"
        assert benchmark.rule_based_tests_executed == 5
        assert benchmark.ml_guided_tests_executed == 5
        assert benchmark.rule_based_verdict == "VERIFIED"
        assert benchmark.ml_guided_verdict == "VERIFIED"
        assert benchmark.rule_based_time_ms >= 0
        assert benchmark.ml_guided_time_ms >= 0
        assert len(benchmark.categories_covered_ml) >= 2
    finally:
        vuln_app.close()
        patch_app.close()


def test_api_refine_patch_endpoint():
    """Verify POST /api/lab/refine-patch endpoint."""
    req = PatchRefineRequest(
        original_source=VULNERABLE_SOURCE,
        current_patch=FLAWED_SANITIZER_CODE,
        max_attempts=3,
    )
    resp = refine_sql_patch(req)

    assert resp.is_fully_refined is True
    assert resp.attempts_made <= 3
    assert len(resp.candidates) >= 1
    assert resp.final_ml_analysis.risk_score <= 0.25


def test_api_compare_planners_endpoint():
    """Verify POST /api/lab/compare-planners endpoint."""
    req = VerificationRequest(
        scenario="valid_parameterized",
        budget_preset="quick",
        max_tests=5,
    )
    resp = compare_planners_endpoint(req)

    assert resp.scenario_id == "valid_parameterized"
    assert resp.rule_based_verdict == "VERIFIED"
    assert resp.ml_guided_verdict == "VERIFIED"
