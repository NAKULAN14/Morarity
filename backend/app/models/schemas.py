from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnalysisFinding(BaseModel):
    rule_id: str
    message: str
    severity: FindingSeverity
    line: Optional[int] = None
    evidence: Optional[str] = None


class AnalysisResult(BaseModel):
    supported: bool
    vulnerability_type: Optional[str] = None
    findings: list[AnalysisFinding] = Field(default_factory=list)
    security_invariants: list[str] = Field(default_factory=list)
    summary: str


class MLAnalysisResult(BaseModel):
    model_status: str = "trained"  # "trained" | "unavailable" | "untrained" | "error"
    predicted_class: str = "unknown"
    risk_score: float = 0.0
    risk_level: str = "LOW"
    detected_features: list[str] = Field(default_factory=list)
    recommended_test_categories: list[str] = Field(default_factory=list)
    model_version: str = "1.0.0"
    summary: str = ""


class LLMReasoningResult(BaseModel):
    """
    Structured outcome of LLM-assisted security reasoning.
    Advisory only: does not independently determine the final verification verdict.
    """
    summary: str = ""
    hypotheses: list[str] = Field(default_factory=list)
    suspicious_code_regions: list[str] = Field(default_factory=list)
    recommended_test_categories: list[str] = Field(default_factory=list)
    additional_test_suggestions: list[dict[str, Any]] = Field(default_factory=list)
    patch_concerns: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    limitations: list[str] = Field(default_factory=list)
    model_name: str = "moriarty-reasoner-v1"
    status: str = "ACTIVE"  # "ACTIVE" | "FALLBACK" | "UNAVAILABLE"
    latency_ms: float = 0.0


class EvidenceGraphNode(BaseModel):
    id: str
    type: str  # "SOURCE" | "PARSED_STRUCTURE" | "SECURITY_FINDING" | "ML_RISK" | "LLM_HYPOTHESIS" | "TEST_DECISION" | "TEST_EXECUTION" | "EVIDENCE_RECORD" | "CANDIDATE_PATCH" | "VERDICT"
    label: str
    status: str  # "PREDICTED" | "HYPOTHESIS" | "PROPOSED" | "EXECUTED" | "CONFIRMED" | "CONTRADICTED" | "VERIFIED" | "REJECTED" | "INCONCLUSIVE"
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[str] = None
    code_location: Optional[str] = None


class EvidenceGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str  # "PARSED_TO" | "INFORMS" | "HYPOTHESIZES" | "PLANS" | "EXECUTES" | "PRODUCES_EVIDENCE" | "SUPPORTS" | "CONTRADICTS" | "REFINES" | "EVALUATED_AS"


class EvidenceGraphData(BaseModel):
    nodes: list[EvidenceGraphNode] = Field(default_factory=list)
    edges: list[EvidenceGraphEdge] = Field(default_factory=list)
    summary: str = ""


class FunctionalityInvariant(BaseModel):
    """
    Configurable invariant specifying benign functional requirements
    that must be preserved after patching.
    """
    invariant_id: str = "FUNC_INVARIANT_001"
    name: str = "Benign User Lookup"
    description: str = "Verify that querying a known valid username returns the expected record"
    input_value: str = "alice"
    expected_field: str = "username"
    expected_value: str = "alice"
    expected_count: int = 1
    is_required: bool = True

    @classmethod
    def default_fixture_invariant(cls) -> "FunctionalityInvariant":
        return cls(
            invariant_id="FUNC_INVARIANT_ALICE",
            name="Default Benign User Lookup",
            description="Ensure legitimate lookup for 'alice' returns exactly Alice's record",
            input_value="alice",
            expected_field="username",
            expected_value="alice",
            expected_count=1,
            is_required=True,
        )


class VerificationTest(BaseModel):
    __test__ = False
    test_id: str
    name: str
    description: str
    test_type: str
    payload: Optional[str] = None


class TestResult(BaseModel):
    __test__ = False
    test_id: str
    passed: bool
    outcome: str
    details: str
    execution_time_ms: Optional[float] = None
    error: Optional[str] = None
    expected_behavior: Optional[str] = None
    observed_behavior: Optional[str] = None
    baseline_exploitable: Optional[bool] = None
    patch_blocks_payload: Optional[bool] = None
    functionality_intact: Optional[bool] = None
    category: Optional[str] = None
    security_invariant: Optional[str] = None


class VerificationCoverage(BaseModel):
    tests_available: int = 0
    tests_selected: int = 0
    tests_executed: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    tests_inconclusive: int = 0
    tests_not_applicable: int = 0
    categories_covered: list[str] = Field(default_factory=list)
    invariants_verified: list[str] = Field(default_factory=list)
    remaining_coverage_gaps: list[str] = Field(default_factory=list)
    coverage_percentage: float = 0.0


class Evidence(BaseModel):
    evidence_id: str
    test_id: str
    category: str
    description: str
    observed: Any
    supports_verification: bool
    timestamp: Optional[str] = None


class VerificationRequest(BaseModel):
    source_code: Optional[str] = None
    original_source: Optional[str] = None
    patched_source: Optional[str] = None
    scenario: Optional[str] = None
    target_type: Optional[str] = "SUBMITTED_SOURCE_EXECUTION"
    execute_submitted_source: Optional[bool] = True
    max_tests: Optional[int] = 5
    budget_preset: Optional[str] = "quick"


class VerificationResponse(BaseModel):
    verification_id: str
    verdict: Verdict
    summary: str
    analysis: AnalysisResult
    tests_executed: list[TestResult] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    verification_scope: Optional[str] = None
    dynamic_verification_performed: Optional[bool] = None
    target_type: Optional[str] = None
    target_provenance: Optional[str] = None
    submitted_source_executed: Optional[bool] = None
    source_runtime_match: Optional[bool] = None
    final_action: Optional[str] = None
    stopping_reason: Optional[str] = None
    decision_trace: Optional[list[dict[str, Any]]] = None
    patch_comparison: Optional[dict[str, Any]] = None
    scenario_id: Optional[str] = None
    coverage: Optional[VerificationCoverage] = None
    original_ml_analysis: Optional[MLAnalysisResult] = None
    patched_ml_analysis: Optional[MLAnalysisResult] = None
    llm_reasoning: Optional[LLMReasoningResult] = None
    evidence_graph: Optional[EvidenceGraphData] = None


class SQLAnalysisRequest(BaseModel):
    input_text: str
    input_type: Optional[str] = "auto"


class SQLAnalysisResponse(BaseModel):
    input_kind: str
    is_vulnerable: bool
    vulnerability_type: Optional[str] = None
    severity: FindingSeverity
    confidence: str
    detected_table: Optional[str] = None
    detected_parameters: list[str] = Field(default_factory=list)
    findings: list[AnalysisFinding] = Field(default_factory=list)
    security_invariants: list[str] = Field(default_factory=list)
    potential_payloads: list[str] = Field(default_factory=list)
    summary: str
    ml_analysis: Optional[MLAnalysisResult] = None
    llm_reasoning: Optional[LLMReasoningResult] = None


class PatchGenerationRequest(BaseModel):
    input_text: str
    input_type: Optional[str] = "auto"
    strategy: Optional[str] = "parameterize"
    param_name: Optional[str] = None


class PatchGenerationResponse(BaseModel):
    original_input: str
    patched_code: str
    patched_sql: Optional[str] = None
    executable_original_source: str
    executable_patched_source: str
    input_kind: str
    technique: str
    generation_method: str
    technical_explanation: str
    invariants_enforced: list[str] = Field(default_factory=list)
    diff_lines: list[dict[str, Any]] = Field(default_factory=list)
    is_verified: bool = False
    ml_analysis: Optional[MLAnalysisResult] = None


class PatchRefinementCandidate(BaseModel):
    attempt: int
    patch_code: str
    diff_lines: list[dict[str, Any]] = Field(default_factory=list)
    ml_risk_score: float
    ml_risk_level: str
    unresolved_findings: list[str] = Field(default_factory=list)
    explanation: str


class PatchRefineRequest(BaseModel):
    original_source: str
    current_patch: str
    max_attempts: int = 3
    input_type: str = "auto"
    param_name: Optional[str] = None


class PatchRefineResponse(BaseModel):
    original_source: str
    final_patch: str
    attempts_made: int
    max_attempts: int
    is_fully_refined: bool
    original_ml_analysis: MLAnalysisResult
    final_ml_analysis: MLAnalysisResult
    candidates: list[PatchRefinementCandidate] = Field(default_factory=list)
    refinement_summary: str


class PlannerComparisonResult(BaseModel):
    scenario_id: str
    scenario_name: str
    rule_based_tests_executed: int
    ml_guided_tests_executed: int
    rule_based_verdict: str
    ml_guided_verdict: str
    ml_risk_score: float
    rule_based_time_ms: float
    ml_guided_time_ms: float
    categories_covered_rule: list[str] = Field(default_factory=list)
    categories_covered_ml: list[str] = Field(default_factory=list)
    efficiency_gain_pct: float
    comparison_summary: str


class LabVerificationRequest(BaseModel):
    original_source: str
    candidate_patch: str
    input_kind: Optional[str] = "PYTHON_CODE"
    source_revision: Optional[int] = 1
    patch_revision: Optional[int] = 1
    max_tests: Optional[int] = 5
    budget_preset: Optional[str] = "quick"


class ContinuousEvaluationRequest(BaseModel):
    source_code: str
    patch_code: Optional[str] = None
    source_revision: int = 1
    patch_revision: int = 1
    auto_verify: bool = False
    max_tests: Optional[int] = 5
    budget_preset: Optional[str] = "quick"


class ContinuousEvaluationResponse(BaseModel):
    source_revision: int
    patch_revision: int
    is_stale: bool
    status: str
    analysis: SQLAnalysisResponse
    generated_patch: Optional[PatchGenerationResponse] = None
    verification_result: Optional[VerificationResponse] = None
    coverage: Optional[VerificationCoverage] = None
    evidence_graph: Optional[EvidenceGraphData] = None


class ComprehensiveBenchmarkMetrics(BaseModel):
    planner_mode: str
    total_runs: int
    avg_tests_executed: float
    avg_time_ms: float
    recall: float
    precision: float
    f1_score: float
    false_positive_rate: float
    verified_count: int
    rejected_count: int
    inconclusive_count: int
    categories_covered: list[str] = Field(default_factory=list)
    efficiency_score: float


class ComprehensiveBenchmarkResponse(BaseModel):
    dataset_size: int
    planners: dict[str, ComprehensiveBenchmarkMetrics]
    comparisons: list[PlannerComparisonResult] = Field(default_factory=list)
    summary: str


class CatalogTestCaseSchema(BaseModel):
    test_id: str
    name: str
    category: str
    dialect: str
    query_context: str
    input_type: str
    security_invariant: str
    payload: str
    expected_behavior: str
    execution_support: str
    verification_weight: str
    is_benign: bool
    description: str


class CatalogCategorySchema(BaseModel):
    name: str
    total_tests: int
    supported_tests: int
    unsupported_tests: int
    is_executable_in_sqlite: bool


class CatalogResponse(BaseModel):
    categories: list[CatalogCategorySchema]
    total_tests: int
    executable_tests: int
    unsupported_tests: int
    tests: list[CatalogTestCaseSchema]


