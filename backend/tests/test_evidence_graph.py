"""
Tests for Verification Evidence Graph and Comprehensive Benchmarking.
Enforces that evidence graph nodes accurately trace source code to verdict,
distinguishes predicted vs confirmed findings, and verifies benchmarking metrics.
"""

from app.agent.agent_loop import MoriartyAgentLoop
from app.agent.planner import AgentPlanner
from app.models.schemas import EvidenceGraphData, ComprehensiveBenchmarkResponse
from app.verification.evidence_graph import EvidenceGraph
from app.scenarios.vulnerable import SOURCE_CODE as VULN_SOURCE
from app.scenarios.correct_patch import SOURCE_CODE as PATCH_SOURCE
from app.scenarios.incomplete_patch import SOURCE_CODE as INCOMPLETE_SOURCE


def test_evidence_graph_builder_creates_traceable_dag():
    graph_builder = EvidenceGraph()
    data = graph_builder.build_verification_graph(
        source_code=VULN_SOURCE,
        patch_code=PATCH_SOURCE,
        ast_findings=[],
        ml_analysis=None,
        llm_reasoning=None,
        decision_trace=[{"action": "RUN_TEST", "strategy": "SQLI_QUOTE_001"}],
        tests_executed=[],
        evidence_records=[],
        verdict="VERIFIED",
        verdict_summary="Patch parameterized query successfully.",
    )
    assert isinstance(data, EvidenceGraphData)
    node_types = {n.type for n in data.nodes}
    assert "SOURCE" in node_types
    assert "PARSED_STRUCTURE" in node_types
    assert "TEST_DECISION" in node_types
    assert "VERDICT" in node_types
    assert "CANDIDATE_PATCH" in node_types

    edge_relations = {e.relation for e in data.edges}
    assert "PARSED_TO" in edge_relations
    assert "PLANS" in edge_relations
    assert "REFINES" in edge_relations


def test_agent_loop_attaches_evidence_graph_and_llm_reasoning():
    agent = MoriartyAgentLoop(max_tests=3)
    result = agent.run(
        original_source=VULN_SOURCE,
        patched_source=PATCH_SOURCE,
        execute_submitted_source=True,
    )
    resp = result.verification_response
    assert resp is not None
    assert resp.evidence_graph is not None
    assert len(resp.evidence_graph.nodes) > 4
    assert len(resp.evidence_graph.edges) > 3
    assert resp.llm_reasoning is not None
    assert resp.llm_reasoning.status == "ACTIVE"


def test_comprehensive_benchmarking_measures_all_four_planners():
    planner = AgentPlanner(max_tests=3)
    test_cases = [
        {
            "id": "valid_test",
            "name": "Valid Parameterized",
            "original_source": VULN_SOURCE,
            "patched_source": PATCH_SOURCE,
            "expected_verdict": "VERIFIED",
        },
        {
            "id": "incomplete_test",
            "name": "Incomplete Sanitizer",
            "original_source": VULN_SOURCE,
            "patched_source": INCOMPLETE_SOURCE,
            "expected_verdict": "REJECTED",
        },
    ]

    res = planner.benchmark_comprehensive(test_cases, budget=3)
    assert isinstance(res, ComprehensiveBenchmarkResponse)
    assert res.dataset_size == 2
    assert "rule_based" in res.planners
    assert "ml_guided" in res.planners
    assert "llm_assisted" in res.planners
    assert "combined" in res.planners

    # Combined planner metrics check
    combined_m = res.planners["combined"]
    assert combined_m.total_runs == 2
    assert combined_m.recall >= 0.99
    assert combined_m.false_positive_rate == 0.0
