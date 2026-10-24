export type VerdictType = 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE';

export type FindingSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type BudgetPreset = 'quick' | 'standard' | 'thorough' | 'custom';

export interface VerificationCoverage {
  tests_available: number;
  tests_selected: number;
  tests_executed: number;
  tests_passed: number;
  tests_failed: number;
  tests_inconclusive: number;
  tests_not_applicable: number;
  categories_covered: string[];
  invariants_verified: string[];
  remaining_coverage_gaps: string[];
  coverage_percentage: number;
}

export interface CatalogTestCase {
  test_id: string;
  name: string;
  category: string;
  dialect: string;
  query_context: string;
  input_type: string;
  security_invariant: string;
  payload: string;
  expected_behavior: string;
  execution_support: string;
  verification_weight: string;
  is_benign: boolean;
  description: string;
}

export interface CatalogCategory {
  name: string;
  total_tests: number;
  supported_tests: number;
  unsupported_tests: number;
  is_executable_in_sqlite: boolean;
}

export interface CatalogResponse {
  categories: CatalogCategory[];
  total_tests: number;
  executable_tests: number;
  unsupported_tests: number;
  tests: CatalogTestCase[];
}

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
  category?: string | null;
  security_invariant?: string | null;
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
  coverage?: VerificationCoverage | null;
  original_ml_analysis?: MLAnalysisResult | null;
  patched_ml_analysis?: MLAnalysisResult | null;
  ml_guided_mode?: boolean | null;
  llm_reasoning?: LLMReasoningResult | null;
  evidence_graph?: EvidenceGraphData | null;
}

export interface VerificationRequest {
  source_code?: string;
  original_source?: string;
  patched_source?: string;
  scenario?: string;
  target_type?: string;
  execute_submitted_source?: boolean;
  max_tests?: number;
  budget_preset?: BudgetPreset | null;
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

export type LabContinuousMode = 'manual' | 'auto_analyze' | 'auto_verify';

export type LabStatus =
  | 'IDLE'
  | 'ANALYZING'
  | 'VULNERABILITY_DETECTED'
  | 'PATCH_GENERATING'
  | 'VERIFYING'
  | 'VERIFIED'
  | 'REJECTED'
  | 'INCONCLUSIVE'
  | 'STALE'
  | 'SAFE'
  | 'ERROR';

export interface MLAnalysisResult {
  model_status: 'trained' | 'fallback' | 'uninitialized';
  predicted_class: 'vulnerable' | 'safe';
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  probability_vulnerable: number;
  probability_safe: number;
  detected_features: string[];
  recommended_test_categories: string[];
  model_version: string;
  summary: string;
}

export interface PatchRefinementCandidate {
  attempt: number;
  patch_code: string;
  diff_lines?: DiffLine[];
  ml_risk_score: number;
  ml_risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  unresolved_findings: string[];
  explanation: string;
}

export interface PatchRefineRequest {
  original_source: string;
  current_patch: string;
  max_attempts?: number;
  input_type?: string;
  param_name?: string;
}

export interface PatchRefineResponse {
  original_source: string;
  final_patch: string;
  attempts_made: number;
  max_attempts: number;
  is_fully_refined: boolean;
  original_ml_analysis: MLAnalysisResult;
  final_ml_analysis: MLAnalysisResult;
  candidates: PatchRefinementCandidate[];
  refinement_summary: string;
}

export interface PlannerComparisonResult {
  scenario_id: string;
  scenario_name: string;
  rule_based_tests_executed: number;
  ml_guided_tests_executed: number;
  rule_based_verdict: string;
  ml_guided_verdict: string;
  ml_risk_score: number;
  rule_based_time_ms: number;
  ml_guided_time_ms: number;
  categories_covered_rule: string[];
  categories_covered_ml: string[];
  efficiency_gain_pct: number;
  comparison_summary: string;
}

export interface SQLAnalysisResult {
  input_kind: string;
  is_vulnerable: boolean;
  vulnerability_type?: string | null;
  severity: FindingSeverity;
  confidence: string;
  detected_table?: string | null;
  detected_parameters: string[];
  findings: AnalysisFinding[];
  security_invariants: string[];
  potential_payloads: string[];
  summary: string;
  ml_analysis?: MLAnalysisResult | null;
  llm_reasoning?: LLMReasoningResult | null;
}

export interface DiffLine {
  type: 'unchanged' | 'added' | 'removed';
  line: number;
  text: string;
}

export interface GeneratedPatch {
  original_input: string;
  patched_code: string;
  patched_sql?: string | null;
  executable_original_source: string;
  executable_patched_source: string;
  input_kind: string;
  technique: string;
  generation_method: string;
  technical_explanation: string;
  invariants_enforced: string[];
  diff_lines: DiffLine[];
  is_verified: boolean;
  ml_analysis?: MLAnalysisResult | null;
  refinement_history?: PatchRefinementCandidate[] | null;
}

export interface LabRevisionEntry {
  id: string;
  timestamp: string;
  sourceRevision: number;
  patchRevision: number;
  status: LabStatus;
  verdict?: VerdictType | null;
  testsRun?: number;
  summary: string;
}

export interface LLMReasoningResult {
  summary: string;
  hypotheses: string[];
  suspicious_code_regions: string[];
  recommended_test_categories: string[];
  additional_test_suggestions: any[];
  patch_concerns: string[];
  confidence: number;
  limitations: string[];
  model_name: string;
  status: 'ACTIVE' | 'FALLBACK' | 'UNAVAILABLE';
  latency_ms: number;
}

export interface EvidenceGraphNode {
  id: string;
  type: string;
  label: string;
  status: string;
  details: Record<string, any>;
  timestamp?: string | null;
  code_location?: string | null;
}

export interface EvidenceGraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
}

export interface EvidenceGraphData {
  nodes: EvidenceGraphNode[];
  edges: EvidenceGraphEdge[];
  summary: string;
}

export interface ComprehensiveBenchmarkMetrics {
  planner_mode: string;
  total_runs: number;
  avg_tests_executed: number;
  avg_time_ms: number;
  recall: number;
  precision: number;
  f1_score: number;
  false_positive_rate: number;
  verified_count: number;
  rejected_count: number;
  inconclusive_count: number;
  categories_covered: string[];
  efficiency_score: number;
}

export interface ComprehensiveBenchmarkResponse {
  dataset_size: number;
  planners: Record<string, ComprehensiveBenchmarkMetrics>;
  comparisons: PlannerComparisonResult[];
  summary: string;
}


