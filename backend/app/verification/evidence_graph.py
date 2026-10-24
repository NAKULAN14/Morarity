"""
Verification Evidence Graph for Moriarty.

Constructs an interactive, auditable, and traceable Directed Acyclic Graph (DAG)
connecting source code, AST/grammar decomposition, ML predictions, LLM hypotheses,
adaptive test decisions, dynamic execution traces, empirical evidence, candidate patches,
and the final formal security verdict.

Strict Integrity Rules:
- Distinguishes clearly between PREDICTED (ML), HYPOTHESIS (LLM), PROPOSED (Planner),
  EXECUTED (Runner), CONFIRMED (Evidence), and CONTRADICTED (Disproved claims).
- Suggested tests are NEVER represented as executed tests.
- LLM hypotheses are NEVER represented as empirical proof without confirmation.
"""

from typing import Any, Optional
from uuid import uuid4

from app.models.schemas import (
    AnalysisFinding,
    Evidence,
    EvidenceGraphData,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    LLMReasoningResult,
    MLAnalysisResult,
    TestResult,
)


class EvidenceGraph:
    """
    Manages and builds the verification evidence graph.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, EvidenceGraphNode] = {}
        self.edges: list[EvidenceGraphEdge] = []

    def clear(self) -> None:
        self.nodes.clear()
        self.edges.clear()

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        status: str,
        details: Optional[dict[str, Any]] = None,
        code_location: Optional[str] = None,
    ) -> EvidenceGraphNode:
        node = EvidenceGraphNode(
            id=node_id,
            type=node_type,
            label=label,
            status=status,
            details=details or {},
            code_location=code_location,
        )
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id: str, target_id: str, relation: str) -> Optional[EvidenceGraphEdge]:
        if source_id not in self.nodes or target_id not in self.nodes:
            return None
        edge_id = f"edge_{source_id}_{target_id}_{relation.lower()}"
        edge = EvidenceGraphEdge(
            id=edge_id,
            source=source_id,
            target=target_id,
            relation=relation,
        )
        self.edges.append(edge)
        return edge

    def build_verification_graph(
        self,
        source_code: Optional[str],
        patch_code: Optional[str],
        ast_findings: Optional[list[AnalysisFinding]],
        ml_analysis: Optional[MLAnalysisResult],
        llm_reasoning: Optional[LLMReasoningResult],
        decision_trace: Optional[list[dict[str, Any]]],
        tests_executed: Optional[list[TestResult]],
        evidence_records: Optional[list[Evidence]],
        verdict: str,
        verdict_summary: str,
        target_type: Optional[str] = "SUBMITTED_SOURCE_EXECUTION",
    ) -> EvidenceGraphData:
        """
        Synthesize the complete traceable verification DAG.
        """
        self.clear()

        # 1. Source Node
        src_id = "node_source_input"
        src_preview = (source_code.strip()[:60] + "...") if source_code else "No source code provided"
        self.add_node(
            node_id=src_id,
            node_type="SOURCE",
            label="Submitted Target Code",
            status="CONFIRMED",
            details={"preview": src_preview, "target_type": target_type},
        )

        # 2. Parsed Structure Node
        parse_id = "node_parsed_structure"
        self.add_node(
            node_id=parse_id,
            node_type="PARSED_STRUCTURE",
            label="AST & Query Structure Decomposition",
            status="CONFIRMED",
            details={"findings_count": len(ast_findings or [])},
        )
        self.add_edge(src_id, parse_id, "PARSED_TO")

        # 3. Security Findings
        findings = ast_findings or []
        for idx, f in enumerate(findings):
            find_id = f"node_finding_{idx}"
            self.add_node(
                node_id=find_id,
                node_type="SECURITY_FINDING",
                label=f"Finding: {f.rule_id}",
                status="CONFIRMED",
                details={"rule_id": f.rule_id, "severity": str(f.severity), "message": f.message},
                code_location=f"Line {f.line}" if f.line else None,
            )
            self.add_edge(parse_id, find_id, "INFORMS")

        # 4. ML Risk Node
        ml_id = "node_ml_risk"
        if ml_analysis:
            self.add_node(
                node_id=ml_id,
                node_type="ML_RISK",
                label=f"ML Risk: {ml_analysis.risk_level} ({ml_analysis.risk_score:.2f})",
                status="PREDICTED",
                details={
                    "risk_score": ml_analysis.risk_score,
                    "risk_level": ml_analysis.risk_level,
                    "features": ml_analysis.detected_features,
                    "model_status": ml_analysis.model_status,
                },
            )
            self.add_edge(parse_id, ml_id, "INFORMS")

        # 5. LLM Reasoning Node
        llm_id = "node_llm_reasoning"
        if llm_reasoning and llm_reasoning.hypotheses:
            self.add_node(
                node_id=llm_id,
                node_type="LLM_HYPOTHESIS",
                label=f"LLM Hypothesis ({len(llm_reasoning.hypotheses)} formulated)",
                status="HYPOTHESIS",
                details={
                    "hypotheses": llm_reasoning.hypotheses,
                    "recommended_categories": llm_reasoning.recommended_test_categories,
                    "model_name": llm_reasoning.model_name,
                    "confidence": llm_reasoning.confidence,
                },
            )
            self.add_edge(parse_id, llm_id, "HYPOTHESIZES")
            if ml_analysis:
                self.add_edge(ml_id, llm_id, "INFORMS")

        # 6. Adaptive Test Planning Node
        plan_id = "node_adaptive_planner"
        trace = decision_trace or []
        self.add_node(
            node_id=plan_id,
            node_type="TEST_DECISION",
            label=f"Adaptive Test Plan ({len(trace)} decisions)",
            status="PROPOSED",
            details={"decisions": trace},
        )
        self.add_edge(parse_id, plan_id, "PLANS")
        if ml_analysis:
            self.add_edge(ml_id, plan_id, "PLANS")
        if llm_reasoning and llm_reasoning.hypotheses:
            self.add_edge(llm_id, plan_id, "PLANS")

        # 7. Executed Tests
        tests = tests_executed or []
        test_node_ids = []
        for idx, t in enumerate(tests):
            t_id = f"node_test_{idx}_{t.test_id}"
            test_node_ids.append(t_id)
            self.add_node(
                node_id=t_id,
                node_type="TEST_EXECUTION",
                label=f"Executed: {t.test_id}",
                status="EXECUTED",
                details={
                    "outcome": t.outcome,
                    "passed": t.passed,
                    "execution_time_ms": t.execution_time_ms,
                    "category": t.category,
                    "security_invariant": t.security_invariant,
                    "baseline_exploitable": t.baseline_exploitable,
                    "patch_blocks_payload": t.patch_blocks_payload,
                    "functionality_intact": t.functionality_intact,
                },
            )
            self.add_edge(plan_id, t_id, "EXECUTES")

        # 8. Evidence Records
        evidence = evidence_records or []
        ev_node_ids = []
        for idx, ev in enumerate(evidence):
            ev_id = f"node_evidence_{idx}_{ev.evidence_id}"
            ev_node_ids.append(ev_id)
            status_ev = "CONFIRMED" if ev.supports_verification else "CONTRADICTED"
            self.add_node(
                node_id=ev_id,
                node_type="EVIDENCE_RECORD",
                label=f"Evidence: {ev.category}",
                status=status_ev,
                details={
                    "description": ev.description,
                    "supports_verification": ev.supports_verification,
                    "observed": ev.observed,
                },
            )
            # Connect to matching test if possible
            connected = False
            for t_node_id in test_node_ids:
                if ev.test_id in t_node_id:
                    self.add_edge(t_node_id, ev_id, "PRODUCES_EVIDENCE")
                    connected = True
                    break
            if not connected and test_node_ids:
                self.add_edge(test_node_ids[0], ev_id, "PRODUCES_EVIDENCE")

        # 9. Candidate Patch Node
        patch_id = "node_candidate_patch"
        if patch_code:
            patch_preview = (patch_code.strip()[:60] + "...") if patch_code else "Candidate patch"
            self.add_node(
                node_id=patch_id,
                node_type="CANDIDATE_PATCH",
                label="Candidate Security Patch",
                status="CONFIRMED",
                details={"preview": patch_preview},
            )
            self.add_edge(src_id, patch_id, "REFINES")

        # 10. Verdict Node
        verdict_str = getattr(verdict, "value", str(verdict))
        verdict_id = "node_verdict"
        self.add_node(
            node_id=verdict_id,
            node_type="VERDICT",
            label=f"Verdict: {verdict_str}",
            status=verdict_str,
            details={"verdict": verdict_str, "summary": verdict_summary},
        )

        for ev_id in ev_node_ids:
            relation = "SUPPORTS" if self.nodes[ev_id].status == "CONFIRMED" else "CONTRADICTS"
            self.add_edge(ev_id, verdict_id, relation)

        if not ev_node_ids:
            self.add_edge(plan_id, verdict_id, "EVALUATED_AS")

        if patch_code:
            self.add_edge(patch_id, verdict_id, "EVALUATED_AS")

        return self.to_dict(verdict_summary)

    def to_dict(self, summary: str = "") -> EvidenceGraphData:
        return EvidenceGraphData(
            nodes=list(self.nodes.values()),
            edges=self.edges,
            summary=summary or f"Evidence graph with {len(self.nodes)} nodes and {len(self.edges)} edges.",
        )
