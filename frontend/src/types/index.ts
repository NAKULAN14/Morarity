export type VerdictType = 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE';

export type FindingSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface AnalysisFinding {
  rule_id: string;
  message: string;
  severity: FindingSeverity;
  line?: number | null;
  evidence?: string | null;
}

export interface AnalysisResult {
  supported: boolean;
  vulnerability_type?: string | null;
  findings: AnalysisFinding[];
  security_invariants: string[];
  summary: string;
}

export interface TestResult {
  test_id: string;
  passed: boolean;
  outcome: string;
  details: string;
  execution_time_ms?: number | null;
  error?: string | null;
  expected_behavior?: string | null;
  observed_behavior?: string | null;
  baseline_exploitable?: boolean | null;
  patch_blocks_payload?: boolean | null;
  functionality_intact?: boolean | null;
}

export interface Evidence {
  evidence_id: string;
  test_id: string;
  category: string;
  description: string;
  observed: Record<string, any>;
  supports_verification: boolean;
  timestamp?: string | null;
}

export interface DecisionTraceStep {
  step: number;
  action: string;
  strategy?: string | null;
  reason: string;
  test_input?: string | null;
  test_outcome?: string | null;
  evidence_id?: string | null;
  stop_reason?: string | null;
  patch_status?: string | null;
  analyzer_findings?: string[];
}

export interface PatchComparisonData {
  status: string;
  summary: string;
  original_rule_ids: string[];
  patched_rule_ids: string[];
  static_improvement_detected: boolean;
  dynamic_verification_performed: boolean;
}

export interface VerificationResponse {
  verification_id: string;
  verdict: VerdictType;
  summary: string;
  analysis: AnalysisResult;
  tests_executed: TestResult[];
  evidence: Evidence[];
  limitations: string[];
  verification_scope?: string | null;
  dynamic_verification_performed?: boolean | null;
  target_type?: string | null;
  target_provenance?: string | null;
  submitted_source_executed?: boolean | null;
  source_runtime_match?: boolean | null;
  final_action?: string | null;
  stopping_reason?: string | null;
  decision_trace?: DecisionTraceStep[] | null;
  patch_comparison?: PatchComparisonData | null;
  scenario_id?: string | null;
}

export interface VerificationRequest {
  source_code?: string;
  original_source?: string;
  patched_source?: string;
  scenario?: string;
  target_type?: string;
  execute_submitted_source?: boolean;
  max_tests?: number;
}

export interface Scenario {
  id: string;
  name: string;
  expected_verdict: VerdictType;
  vulnerability_type: string;
  badge_color: 'green' | 'red' | 'amber';
  description: string;
  original_source: string;
  patched_source: string;
  default_mode: string;
}

export interface ReportSummary {
  filename: string;
  verification_id: string;
  verdict: VerdictType;
  summary: string;
  target_type: string;
  target_provenance: string;
  timestamp: string | number;
  tests_run: number;
  findings_count: number;
  final_action?: string;
  stopping_reason?: string;
}

export interface VerificationStats {
  total_verifications: number;
  verified_count: number;
  rejected_count: number;
  inconclusive_count: number;
  verified_percentage: number;
  recent_verifications: ReportSummary[];
}

export interface BackendHealth {
  status: string;
  service: string;
  version: string;
  engine: string;
  ping_ms?: number;
}
