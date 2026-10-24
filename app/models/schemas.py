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


class VerificationTest(BaseModel):
    test_id: str
    name: str
    description: str
    test_type: str
    payload: Optional[str] = None


class TestResult(BaseModel):
    test_id: str
    passed: bool
    outcome: str
    details: str
    execution_time_ms: Optional[float] = None
    error: Optional[str] = None


class Evidence(BaseModel):
    evidence_id: str
    test_id: str
    category: str
    description: str
    observed: Any
    supports_verification: bool
    timestamp: Optional[str] = None


class VerificationRequest(BaseModel):
    source_code: str = Field(min_length=1)
    scenario: Optional[str] = None


class VerificationResponse(BaseModel):
    verification_id: str
    verdict: Verdict
    summary: str
    analysis: AnalysisResult
    tests_executed: list[TestResult] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
