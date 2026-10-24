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
    max_tests: Optional[int] = 3


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
