import React, { useState } from 'react';
import {
  Layers,
  Shield,
  Cpu,
  Brain,
  Sparkles,
  Database,
  Terminal,
  Activity,
  FileCode,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ArrowRight,
  ArrowDown,
  CheckCircle2,
  Lock,
  GitBranch,
  Network,
  RotateCcw,
  Sliders,
  ExternalLink,
} from 'lucide-react';

interface ComponentDetail {
  id: string;
  name: string;
  category: 'input' | 'analysis' | 'ml' | 'planner' | 'execution' | 'verdict' | 'patch';
  purpose: string;
  responsibilities: string[];
  input: string;
  output: string;
  connectedTo: string[];
  sourceFile: string;
  apiEndpoint?: string;
  notes: string;
}

const COMPONENTS: Record<string, ComponentDetail> = {
  user_input: {
    id: 'user_input',
    name: 'User Input Layer',
    category: 'input',
    purpose: 'Accepts arbitrary raw SQLite SQL statements or complete Python database code using Python sqlite3.',
    responsibilities: [
      'Ingests raw SQL queries (SELECT, INSERT, UPDATE, DELETE, DDL, CTEs, JOINs, PRAGMAs)',
      'Ingests complete Python database functions using cursor.execute() or connection.execute()',
      'Provides continuous real-time debounced input handling in the SQL Security Lab',
    ],
    input: 'Raw SQLite SQL string or Python source code string',
    output: 'Validated source text with input_type parameter (raw_sql | python | auto)',
    connectedTo: ['sqlite_parser', 'ast_analyzer'],
    sourceFile: 'backend/app/patching/sql_analyzer.py',
    apiEndpoint: 'POST /api/lab/analyze, POST /api/verify',
    notes: 'Does not enforce predefined scenario matching or fixed schemas. Arbitrary queries are supported.',
  },
  sqlite_parser: {
    id: 'sqlite_parser',
    name: 'SQLite Parser & Syntax Engine',
    category: 'analysis',
    purpose: 'Performs robust SQLite syntax validation, statement classification, and schema discovery using the native SQLite engine.',
    responsibilities: [
      'Validates syntax using native SQLite EXPLAIN compilation in an isolated in-memory connection',
      'Classifies statements (SELECT, INSERT, UPDATE, DELETE, CREATE_TABLE, CTEs, PRAGMA)',
      'Extracts referenced table names and column identifiers across complex JOINs and clauses',
      'Distinguishes true syntax errors from missing runtime schema context',
      'Provisions mock database tables and synthetic seed data for isolated execution',
    ],
    input: 'Raw SQLite statement string',
    output: 'ParsedSQLiteQuery with statement_type, tables, columns, parameters, and syntax validity',
    connectedTo: ['data_flow', 'ml_analyzer'],
    sourceFile: 'backend/app/analysis/sqlite_parser.py',
    apiEndpoint: 'POST /api/lab/analyze',
    notes: 'Uses the real SQLite C-engine via sqlite3 to guarantee 100% dialect fidelity without fragile regex-only parsing.',
  },
  ast_analyzer: {
    id: 'ast_analyzer',
    name: 'Python AST Data-Flow Analyzer',
    category: 'analysis',
    purpose: 'Parses Python source code into an Abstract Syntax Tree to analyze SQL query construction and data flow.',
    responsibilities: [
      'Parses Python code into AST nodes, rejecting syntactically invalid code',
      'Tracks multi-hop variable assignments from source variables to database execution sinks',
      'Detects dynamic query construction via string concatenation (+), f-strings, %, and .format()',
      'Recognizes parameterized query calls: cursor.execute(query, params) and executemany()',
      'Identifies naive or flawed sanitization routines (e.g. .replace("--", ""))',
    ],
    input: 'Python source code string',
    output: 'AnalysisResult with findings (SQLI_UNSAFE_QUERY, SQLI_PARAMETERIZED_QUERY, etc.)',
    connectedTo: ['data_flow', 'ml_analyzer'],
    sourceFile: 'backend/app/analyzer/ast_analyzer.py',
    apiEndpoint: 'POST /api/lab/analyze',
    notes: 'Does not depend on hardcoded function or variable names. Analyzes arbitrary Python functions.',
  },
  data_flow: {
    id: 'data_flow',
    name: 'Query Extraction & Normalization',
    category: 'analysis',
    purpose: 'Extracts the compiled query structure, isolates dynamic input parameters, and formalizes required security invariants.',
    responsibilities: [
      'Extracts target query strings from Python AST or direct SQL statements',
      'Extracts target parameters and affected database tables',
      'Normalizes source code for cryptographic SHA-256 target provenance checking',
      'Generates fundamental security invariants (e.g. untrusted input must not alter query syntax)',
    ],
    input: 'AST nodes / ParsedSQLiteQuery',
    output: 'Normalized query structures, detected table/column targets, and security invariants',
    connectedTo: ['ml_analyzer', 'patch_generator'],
    sourceFile: 'backend/app/patching/sql_analyzer.py',
    apiEndpoint: 'POST /api/lab/analyze',
    notes: 'Preserves string literals and hash symbols inside literals during normalization.',
  },
  ml_analyzer: {
    id: 'ml_analyzer',
    name: 'ML Risk Classifier (TF-IDF + Logistic Regression)',
    category: 'ml',
    purpose: 'Machine learning inference pipeline trained on SQL injection patterns to evaluate vulnerability risk and extract query features.',
    responsibilities: [
      'Transforms code into character n-grams (range 2-5) using TF-IDF vectorization',
      'Executes calibrated Logistic Regression inference to produce continuous posterior probabilities [0.0, 1.0]',
      'Assigns discrete operational risk levels (LOW, MEDIUM, HIGH, CRITICAL)',
      'Extracts structural risk features (e.g. string_concatenation_in_query, quote_delimiters)',
      'Recommends prioritized test categories to the Adaptive Test Planner',
      'Independently evaluates BOTH original submitted code and generated candidate patches',
    ],
    input: 'Source code or candidate patch string',
    output: 'MLAnalysisResult (risk_score, risk_level, detected_features, recommended_test_categories)',
    connectedTo: ['adaptive_planner', 'refinement_loop'],
    sourceFile: 'backend/app/ml/ml_analyzer.py',
    apiEndpoint: 'Included in POST /api/lab/analyze, POST /api/verify',
    notes: 'CRITICAL SECURITY BOUNDARY: The ML model is advisory. It can NEVER declare a fix verified or secure on its own. Empirical dynamic tests are strictly required.',
  },
  llm_reasoner: {
    id: 'llm_reasoner',
    name: 'LLM Security Reasoning & Hypothesis Layer',
    category: 'analysis',
    purpose: 'Formulates structured security hypotheses, contextual test suggestions, and explains patch diffs for unfamiliar SQL structures.',
    responsibilities: [
      'Analyzes parsed AST findings, query parameters, and ML risk scores',
      'Formulates contextual security hypotheses (delimiter boundary breakout, tautology predicates)',
      'Generates targeted challenge test suggestions tailored to discovered query structures',
      'Explains candidate patch residual concerns and flags naive sanitization attempts',
      'Operates with graceful local heuristic fallback when external provider keys are absent',
    ],
    input: 'Source code, AST findings, ML risk score and detected features',
    output: 'LLMReasoningResult (hypotheses, recommended categories, test suggestions, patch concerns, confidence)',
    connectedTo: ['adaptive_planner', 'refinement_loop'],
    sourceFile: 'backend/app/llm/reasoner.py',
    apiEndpoint: 'Included in POST /api/lab/analyze, POST /api/verify',
    notes: 'CRITICAL SECURITY BOUNDARY: The LLM is strictly advisory. It proposes hypotheses and suggests test challenges, but cannot independently determine security verdicts.',
  },
  evidence_graph: {
    id: 'evidence_graph',
    name: 'Verification Evidence Graph (Traceability DAG)',
    category: 'verdict',
    purpose: 'Constructs an interactive Directed Acyclic Graph connecting source code to the final formal verdict.',
    responsibilities: [
      'Connects SOURCE -> PARSED_STRUCTURE -> FINDINGS -> ML/LLM -> TEST_DECISION -> TEST_EXECUTION -> EVIDENCE -> VERDICT',
      'Distinguishes between PREDICTED, HYPOTHESIS, PROPOSED, EXECUTED, CONFIRMED, and CONTRADICTED nodes',
      'Enforces complete traceability preventing unsupported security assertions',
      'Exposes inspectable provenance attributes and relational edges',
    ],
    input: 'Source, AST findings, ML risk, LLM reasoning, test traces, ledger evidence, final verdict',
    output: 'EvidenceGraphData (nodes with status, edges with typed relations)',
    connectedTo: ['verdict_engine'],
    sourceFile: 'backend/app/verification/evidence_graph.py',
    apiEndpoint: 'Included in POST /api/lab/verify-patch',
    notes: 'Eliminates black-box assertions. Every formal verdict has a cryptographically traceable path of empirical proof.',
  },
  patch_generator: {
    id: 'patch_generator',
    name: 'Deterministic AST Patch Generator',
    category: 'patch',
    purpose: 'Transforms vulnerable SQL queries or Python code into secure parameterized implementations using syntax rewriting.',
    responsibilities: [
      'Rewrites unparameterized WHERE, VALUES, or SET literals into SQLite "?" parameter markers',
      'Rewrites dynamic Python concatenation into parameterized cursor.execute(sql, (param,)) tuples',
      'Preserves original function names, argument signatures, and database table names',
      'Generates line-by-line structured diffs and technical remediation explanations',
      'Marks all generated patches strictly as UNVERIFIED CANDIDATES (is_verified = False)',
    ],
    input: 'Vulnerable SQL query or Python source code',
    output: 'GeneratedPatch with patched_code, diff_lines, invariants_enforced, is_verified = False',
    connectedTo: ['refinement_loop', 'dynamic_runner'],
    sourceFile: 'backend/app/patching/generator.py',
    apiEndpoint: 'POST /api/lab/generate-patch',
    notes: 'INDEPENDENCE GUARANTEE: The patch generator does not score or verify its own code. Candidate patches are independently analyzed by the ML analyzer and verified by the differential runner.',
  },
  refinement_loop: {
    id: 'refinement_loop',
    name: 'Bounded Patch Refinement Loop',
    category: 'patch',
    purpose: 'Iteratively refines candidate patches across bounded attempts (max 3), re-evaluating each attempt with independent AST and ML analyzers.',
    responsibilities: [
      'Accepts an initial candidate patch (e.g. a flawed sanitizer with remaining quote vulnerabilities)',
      'Re-analyzes the candidate using independent static AST analyzer and ML risk classifier',
      'Detects residual vulnerabilities or incomplete filter bypasses',
      'Transforms AST into clean parameter tuple bindings',
      'Stores candidate history, diffs, and before/after ML risk scores per attempt',
      'Stops when all invariants are satisfied or when max_attempts is reached',
    ],
    input: 'Original source and candidate patch, max_attempts (default 3)',
    output: 'PatchRefineResponse (attempts_made, candidates history, original_ml_risk, refined_ml_risk, final_patch)',
    connectedTo: ['dynamic_runner'],
    sourceFile: 'backend/app/patching/generator.py',
    apiEndpoint: 'POST /api/lab/refine-patch',
    notes: 'Bounded loop guarantees termination without recursion. Candidate history allows full forensic audit of patch evolution.',
  },
  adaptive_planner: {
    id: 'adaptive_planner',
    name: 'ML-Guided Adaptive Test Planner',
    category: 'planner',
    purpose: 'Dynamically sequences challenge probes against the patched target, prioritizing test categories based on ML risk features.',
    responsibilities: [
      'Supports two planning modes: rule_based (sequential) and ml_guided (risk-prioritized)',
      'Ingests ML recommended categories to challenge specific syntactic boundaries first',
      'Adapts subsequent probes based on empirical observations from preceding tests',
      'Articulates explainable dynamic decision reasons in the agent decision trace',
      'Respects configurable test budgets (quick=5, standard=15, thorough=30, custom)',
      'Executes side-by-side planner benchmarking (compare_planners) tracking duration and bypass efficiency',
    ],
    input: 'Analysis findings, MLAnalysisResult, previous probe results, test budget',
    output: 'PlanDecision (RUN_TEST with selected test case and payload, or STOP action)',
    connectedTo: ['dynamic_runner'],
    sourceFile: 'backend/app/agent/planner.py',
    apiEndpoint: 'POST /api/lab/compare-planners',
    notes: 'Does not loop indefinitely; stops early upon detecting an invariant violation (STOP_REJECTED) or when the budget completes with all requirements satisfied.',
  },
  dynamic_runner: {
    id: 'dynamic_runner',
    name: 'Isolated Differential Verification Runner',
    category: 'execution',
    purpose: 'Executes controlled security tests against isolated in-memory SQLite targets, comparing vulnerable baseline and candidate patch behavior.',
    responsibilities: [
      'Compiles submitted code in a restricted namespace with isolated in-memory SQLite database',
      'Provisions mock database schema and synthetic rows matching discovered tables and columns',
      'Tests 40 catalog probes across 12 categories (quotes, booleans, unions, stacked queries, errors)',
      'Checks baseline exploitability: does the payload alter query syntax or leak unauthorized records?',
      'Checks patch neutralization: does the patched target treat the payload strictly as literal data?',
      'Checks functionality preservation: do legitimate benign inputs continue to return expected records?',
      'Tracks driver restrictions (e.g. SQLite stacked queries) as not_applicable rather than false passes',
    ],
    input: 'Test payload, isolated runtime apps, functionality invariant',
    output: 'LocalAppTestResult (baseline_exploitable, patch_blocks_payload, functionality_intact, execution_time_ms)',
    connectedTo: ['evidence_ledger'],
    sourceFile: 'backend/app/execution/local_app_runner.py, backend/app/execution/differential_runner.py',
    apiEndpoint: 'POST /api/lab/verify-patch, POST /api/verify',
    notes: 'Never executes code on the host system directly; uses restricted in-memory execution. Captures SQL errors and query results safely.',
  },
  evidence_ledger: {
    id: 'evidence_ledger',
    name: 'Forensic Evidence Ledger & Provenance',
    category: 'verdict',
    purpose: 'Collects tamper-evident empirical verification evidence and enforces cryptographic target provenance.',
    responsibilities: [
      'Validates target provenance via SHA-256 hash matching between submitted code and runtime object',
      'Rejects mismatched targets with PROVENANCE_MISMATCH to prevent false safety claims',
      'Records structured evidence items with UUID, category, observed results, and verification support flags',
      'Enforces strict anti-forgery invariants: simulated fixtures can never certify submitted patches',
      'Tracks test execution coverage and remaining coverage gaps',
    ],
    input: 'LocalAppTestResult observations, provenance verification results',
    output: 'Evidence ledger items, verification coverage metrics, target provenance status',
    connectedTo: ['verdict_engine'],
    sourceFile: 'backend/app/verification/evidence_ledger.py, backend/app/execution/source_executor.py',
    apiEndpoint: 'Included in verification response',
    notes: 'Prevents provenance confusion where a benign static check might be used to falsely verify unrelated vulnerable code.',
  },
  verdict_engine: {
    id: 'verdict_engine',
    name: 'Evidence-Based Verdict Engine',
    category: 'verdict',
    purpose: 'Evaluates recorded dynamic evidence against strict security requirements to issue an authoritative formal audit verdict.',
    responsibilities: [
      'Enforces the three-outcome model: VERIFIED, REJECTED, INCONCLUSIVE',
      'Requires baseline exploitability + patch neutralization + intact functionality for VERIFIED',
      'Issues REJECTED exclusively when direct evidence proves the patched target remains exploitable',
      'Issues INCONCLUSIVE for broken functionality, runtime errors, missing context, or budget exhaustion',
      'Accompanies every verdict with an explicit verification scope and meaningful stopping reason',
      'Serializes final formal audit reports to disk as JSON',
    ],
    input: 'Evidence list, target provenance, functionality check results, budget status',
    output: 'Verdict (VERIFIED | REJECTED | INCONCLUSIVE) and formal audit report',
    connectedTo: [],
    sourceFile: 'backend/app/verification/verdict_engine.py, backend/app/reporting/report_generator.py',
    apiEndpoint: 'POST /api/verify, GET /api/reports/{id}',
    notes: 'Honest uncertainty principle: missing schema, AST limits, or execution errors always preserve INCONCLUSIVE with specific reasons rather than returning a false clean verdict.',
  },
};

export const ArchitectureWorkspace: React.FC = () => {
  const [selectedComponentId, setSelectedComponentId] = useState<string>('ml_analyzer');
  const [activeSection, setActiveSection] = useState<'overview' | 'backend' | 'frontend' | 'dataflow' | 'api' | 'boundaries'>('overview');

  const selectedComp = COMPONENTS[selectedComponentId] || COMPONENTS.ml_analyzer;

  return (
    <div className="space-y-8 py-2 font-mono">
      {/* Workspace Header */}
      <div className="relative overflow-hidden rounded-lg border border-[#222B30] bg-[#0C1013] p-6 sm:p-8">
        <div className="absolute inset-0 bg-tech-grid opacity-20 pointer-events-none" />
        <div className="relative z-10 max-w-4xl space-y-3">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#11171B] border border-[#222B30] text-xs text-[#8B989E]">
            <Layers className="w-3.5 h-3.5 text-[#39E58C]" />
            <span>Moriarty 2.0 System Architecture & Component Visualizer</span>
          </div>
          <h1 className="text-2xl sm:text-4xl font-bold tracking-tight text-[#E8EEF0]">
            Moriarty System Architecture
          </h1>
          <p className="text-xs sm:text-sm text-[#8B989E] font-sans leading-relaxed max-w-3xl">
            ML- and LLM-assisted adaptive security verification with independent patch analysis and evidence-backed verdicts.
            Inspect the complete pipeline from raw SQLite statement parsing to dynamic in-memory differential testing.
          </p>
        </div>
      </div>

      {/* Interactive System Architecture Graph */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-[#38BDF8]" />
            <h2 className="text-sm font-bold text-[#E8EEF0]">
              INTERACTIVE COMPONENT TOPOLOGY
            </h2>
          </div>
          <span className="text-[11px] text-[#536168]">
            Click any component node to inspect responsibilities, I/O schemas, and implementation files
          </span>
        </div>

        {/* Diagram Canvas */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Visual Flow Columns */}
          <div className="lg:col-span-2 bg-[#0C1013] border border-[#222B30] rounded-lg p-5 space-y-6 overflow-x-auto">
            {/* Layer 1: Inputs */}
            <div>
              <div className="text-[10px] text-[#536168] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Terminal className="w-3 h-3 text-[#39E58C]" />
                <span>1. User Input & Ingestion Layer</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <button
                  onClick={() => setSelectedComponentId('user_input')}
                  className={`p-3 rounded text-left border transition-all ${
                    selectedComponentId === 'user_input'
                      ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.2)]'
                      : 'bg-[#07090B] border-[#222B30] hover:border-[#38BDF8]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>Raw SQLite & Python sqlite3</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#11171B] text-[#38BDF8]">INPUT</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Accepts arbitrary SQL queries (SELECT, DDL, CTE) or Python DB code
                  </p>
                </button>

                <button
                  onClick={() => setSelectedComponentId('sqlite_parser')}
                  className={`p-3 rounded text-left border transition-all ${
                    selectedComponentId === 'sqlite_parser'
                      ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.2)]'
                      : 'bg-[#07090B] border-[#222B30] hover:border-[#38BDF8]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>SQLite Parser & Engine</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#11171B] text-[#39E58C]">ENGINE</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Native EXPLAIN syntax validation & dynamic mock schema provisioning
                  </p>
                </button>
              </div>
            </div>

            <div className="flex justify-center">
              <ArrowDown className="w-4 h-4 text-[#536168]" />
            </div>

            {/* Layer 2: Analysis & Taint Flow */}
            <div>
              <div className="text-[10px] text-[#536168] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <FileCode className="w-3 h-3 text-[#38BDF8]" />
                <span>2. Structural Analysis & Data-Flow Layer</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <button
                  onClick={() => setSelectedComponentId('ast_analyzer')}
                  className={`p-3 rounded text-left border transition-all ${
                    selectedComponentId === 'ast_analyzer'
                      ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.2)]'
                      : 'bg-[#07090B] border-[#222B30] hover:border-[#38BDF8]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>Python AST Analyzer</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#11171B] text-[#38BDF8]">AST</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Multi-hop variable taint tracking, f-strings, %, and .format()
                  </p>
                </button>

                <button
                  onClick={() => setSelectedComponentId('data_flow')}
                  className={`p-3 rounded text-left border transition-all ${
                    selectedComponentId === 'data_flow'
                      ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.2)]'
                      : 'bg-[#07090B] border-[#222B30] hover:border-[#38BDF8]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>Query Normalization</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#11171B] text-[#38BDF8]">FLOW</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Extracts table/columns & derives required security invariants
                  </p>
                </button>
              </div>
            </div>

            <div className="flex justify-center">
              <ArrowDown className="w-4 h-4 text-[#536168]" />
            </div>

            {/* Layer 3: Independent ML Classifier */}
            <div>
              <div className="text-[10px] text-[#536168] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Brain className="w-3 h-3 text-[#C084FC]" />
                <span>3. Machine Learning Inference Pipeline (Decoupled & Advisory)</span>
              </div>
              <button
                onClick={() => setSelectedComponentId('ml_analyzer')}
                className={`w-full p-3.5 rounded text-left border transition-all ${
                  selectedComponentId === 'ml_analyzer'
                    ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.3)]'
                    : 'bg-[#07090B] border-[#6366F1]/40 hover:border-[#818CF8]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Brain className="w-4 h-4 text-[#C084FC]" />
                    <span className="text-xs font-bold text-[#E8EEF0]">
                      SQLInjectionMLAnalyzer (TF-IDF 2-5 + Calibrated Logistic Regression)
                    </span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-[#1E1B4B] text-[#A5B4FC] border border-[#6366F1]/40">
                    ADVISORY ML
                  </span>
                </div>
                <div className="mt-2 grid grid-cols-3 gap-2 text-[11px] text-[#8B989E] font-mono">
                  <div className="bg-[#11171B] p-1.5 rounded border border-[#222B30]">
                    <span className="text-[#536168] block text-[9px]">OUTPUT:</span>
                    <span>Risk Score [0.0 - 1.0]</span>
                  </div>
                  <div className="bg-[#11171B] p-1.5 rounded border border-[#222B30]">
                    <span className="text-[#536168] block text-[9px]">FEATURES:</span>
                    <span>Syntax N-Grams</span>
                  </div>
                  <div className="bg-[#11171B] p-1.5 rounded border border-[#222B30]">
                    <span className="text-[#536168] block text-[9px]">PURPOSE:</span>
                    <span>Test Prioritization</span>
                  </div>
                </div>
              </button>
            </div>

            <div className="flex justify-center">
              <ArrowDown className="w-4 h-4 text-[#536168]" />
            </div>

            {/* Layer 4: Decoupled Patch Generator & Refinement Branch */}
            <div className="p-3.5 rounded bg-[#07090B] border border-[#222B30] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-[#C084FC] uppercase tracking-wider flex items-center gap-1.5 font-bold">
                  <GitBranch className="w-3.5 h-3.5" />
                  Independent Patch Generation & Refinement Branch
                </span>
                <span className="text-[10px] text-[#FF5B64] border border-[#FF5B64]/30 px-1.5 py-0.2 rounded bg-[#2B1014]">
                  DOES NOT SELF-VERIFY
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <button
                  onClick={() => setSelectedComponentId('patch_generator')}
                  className={`p-2.5 rounded text-left border transition-all ${
                    selectedComponentId === 'patch_generator'
                      ? 'bg-[#1E1B4B] border-[#818CF8]'
                      : 'bg-[#11171B] border-[#222B30] hover:border-[#C084FC]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>AST Patch Generator</span>
                    <span className="text-[9px] px-1 py-0.2 rounded bg-[#07090B] text-[#C084FC]">CANDIDATE</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Rewrites literals into '?' parameter placeholders (is_verified = False)
                  </p>
                </button>

                <button
                  onClick={() => setSelectedComponentId('refinement_loop')}
                  className={`p-2.5 rounded text-left border transition-all ${
                    selectedComponentId === 'refinement_loop'
                      ? 'bg-[#1E1B4B] border-[#818CF8]'
                      : 'bg-[#11171B] border-[#222B30] hover:border-[#C084FC]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>Patch Refinement Loop</span>
                    <span className="text-[9px] px-1 py-0.2 rounded bg-[#07090B] text-[#C084FC]">MAX 3</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Bounded iterative loop re-scoring candidate with independent AST & ML
                  </p>
                </button>
              </div>
            </div>

            <div className="flex justify-center">
              <ArrowDown className="w-4 h-4 text-[#536168]" />
            </div>

            {/* Layer 5: Adaptive Planner & Differential Execution */}
            <div>
              <div className="text-[10px] text-[#536168] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Sliders className="w-3 h-3 text-[#39E58C]" />
                <span>4. Adaptive Dynamic Planning & Differential Execution</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <button
                  onClick={() => setSelectedComponentId('adaptive_planner')}
                  className={`p-3 rounded text-left border transition-all ${
                    selectedComponentId === 'adaptive_planner'
                      ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.2)]'
                      : 'bg-[#07090B] border-[#222B30] hover:border-[#38BDF8]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>AgentPlanner</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#11171B] text-[#39E58C]">PLANNER</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Prioritizes 40 catalog tests across 12 categories based on ML risk features
                  </p>
                </button>

                <button
                  onClick={() => setSelectedComponentId('dynamic_runner')}
                  className={`p-3 rounded text-left border transition-all ${
                    selectedComponentId === 'dynamic_runner'
                      ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.2)]'
                      : 'bg-[#07090B] border-[#222B30] hover:border-[#38BDF8]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>Differential Runner</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#11171B] text-[#38BDF8]">SANDBOX</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Isolated in-memory SQLite target testing baseline vs candidate patch
                  </p>
                </button>
              </div>
            </div>

            <div className="flex justify-center">
              <ArrowDown className="w-4 h-4 text-[#536168]" />
            </div>

            {/* Layer 6: Evidence & Verdicts */}
            <div>
              <div className="text-[10px] text-[#536168] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <ShieldCheck className="w-3 h-3 text-[#39E58C]" />
                <span>5. Evidence Ledger & Strict Verdict Engine</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <button
                  onClick={() => setSelectedComponentId('evidence_ledger')}
                  className={`p-3 rounded text-left border transition-all ${
                    selectedComponentId === 'evidence_ledger'
                      ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.2)]'
                      : 'bg-[#07090B] border-[#222B30] hover:border-[#38BDF8]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>EvidenceLedger</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#11171B] text-[#39E58C]">LEDGER</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    SHA-256 target provenance & strict proof validation
                  </p>
                </button>

                <button
                  onClick={() => setSelectedComponentId('verdict_engine')}
                  className={`p-3 rounded text-left border transition-all ${
                    selectedComponentId === 'verdict_engine'
                      ? 'bg-[#1E1B4B] border-[#818CF8] shadow-[0_0_12px_rgba(129,140,248,0.2)]'
                      : 'bg-[#07090B] border-[#222B30] hover:border-[#38BDF8]/40'
                  }`}
                >
                  <div className="text-xs font-bold text-[#E8EEF0] flex items-center justify-between">
                    <span>VerdictEngine</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#11171B] text-[#39E58C]">VERDICT</span>
                  </div>
                  <p className="text-[11px] text-[#8B989E] font-sans mt-1">
                    Issues VERIFIED, REJECTED, or INCONCLUSIVE with scope limitations
                  </p>
                </button>
              </div>
            </div>
          </div>

          {/* Component Detail Side Panel */}
          <div className="bg-[#0C1013] border border-[#222B30] rounded-lg p-5 flex flex-col justify-between space-y-4">
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-[#222B30] pb-3">
                <div>
                  <span className="text-[10px] text-[#818CF8] block">COMPONENT DETAILS</span>
                  <h3 className="text-sm font-bold text-[#E8EEF0]">{selectedComp.name}</h3>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#11171B] border border-[#222B30] text-[#8B989E] uppercase">
                  {selectedComp.category}
                </span>
              </div>

              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-[#536168] text-[10px] block font-bold">PURPOSE:</span>
                  <p className="text-[#E8EEF0] leading-relaxed mt-0.5">{selectedComp.purpose}</p>
                </div>

                <div>
                  <span className="text-[#536168] text-[10px] block font-bold">CORE RESPONSIBILITIES:</span>
                  <ul className="space-y-1.5 mt-1 text-[#8B989E]">
                    {selectedComp.responsibilities.map((r, i) => (
                      <li key={i} className="flex items-start gap-1.5 text-[11px]">
                        <span className="text-[#39E58C] font-bold">•</span>
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#222B30]">
                  <div className="bg-[#07090B] p-2 rounded border border-[#222B30]">
                    <span className="text-[#536168] text-[9px] block">INPUT</span>
                    <span className="text-[11px] text-[#8B989E] truncate block">{selectedComp.input}</span>
                  </div>
                  <div className="bg-[#07090B] p-2 rounded border border-[#222B30]">
                    <span className="text-[#536168] text-[9px] block">OUTPUT</span>
                    <span className="text-[11px] text-[#39E58C] truncate block">{selectedComp.output}</span>
                  </div>
                </div>

                <div className="space-y-1.5 pt-2 border-t border-[#222B30]">
                  <div className="flex justify-between items-center text-[11px]">
                    <span className="text-[#536168]">Source File:</span>
                    <code className="text-[#38BDF8] bg-[#07090B] px-1.5 py-0.5 rounded border border-[#222B30]">
                      {selectedComp.sourceFile}
                    </code>
                  </div>
                  {selectedComp.apiEndpoint && (
                    <div className="flex justify-between items-center text-[11px]">
                      <span className="text-[#536168]">API Endpoint:</span>
                      <code className="text-[#C084FC] bg-[#07090B] px-1.5 py-0.5 rounded border border-[#222B30]">
                        {selectedComp.apiEndpoint}
                      </code>
                    </div>
                  )}
                </div>

                <div className="p-2.5 rounded bg-[#07090B] border border-[#222B30] text-[11px] text-[#8B989E] leading-relaxed">
                  <span className="text-[#FFBE55] font-bold block mb-0.5 text-[10px]">INTEGRITY NOTE:</span>
                  {selectedComp.notes}
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-[#222B30] text-[10px] text-[#536168]">
              Verified against Moriarty 2.0 codebase implementation.
            </div>
          </div>
        </div>
      </div>

      {/* Deep Dive Architecture Sections Navigation */}
      <div className="space-y-4">
        <div className="border-b border-[#222B30] flex flex-wrap gap-2 pb-1">
          <button
            onClick={() => setActiveSection('overview')}
            className={`px-3 py-1.5 text-xs font-mono font-medium rounded transition-colors ${
              activeSection === 'overview'
                ? 'bg-[#11171B] text-[#39E58C] border border-[#39E58C]/40'
                : 'text-[#8B989E] hover:text-[#E8EEF0]'
            }`}
          >
            A. System Overview
          </button>
          <button
            onClick={() => setActiveSection('backend')}
            className={`px-3 py-1.5 text-xs font-mono font-medium rounded transition-colors ${
              activeSection === 'backend'
                ? 'bg-[#11171B] text-[#38BDF8] border border-[#38BDF8]/40'
                : 'text-[#8B989E] hover:text-[#E8EEF0]'
            }`}
          >
            B. Backend Architecture
          </button>
          <button
            onClick={() => setActiveSection('frontend')}
            className={`px-3 py-1.5 text-xs font-mono font-medium rounded transition-colors ${
              activeSection === 'frontend'
                ? 'bg-[#11171B] text-[#C084FC] border border-[#C084FC]/40'
                : 'text-[#8B989E] hover:text-[#E8EEF0]'
            }`}
          >
            C. Frontend Workspaces
          </button>
          <button
            onClick={() => setActiveSection('dataflow')}
            className={`px-3 py-1.5 text-xs font-mono font-medium rounded transition-colors ${
              activeSection === 'dataflow'
                ? 'bg-[#11171B] text-[#FFBE55] border border-[#FFBE55]/40'
                : 'text-[#8B989E] hover:text-[#E8EEF0]'
            }`}
          >
            D. Data Flow Lifecycle
          </button>
          <button
            onClick={() => setActiveSection('api')}
            className={`px-3 py-1.5 text-xs font-mono font-medium rounded transition-colors ${
              activeSection === 'api'
                ? 'bg-[#11171B] text-[#E8EEF0] border border-[#222B30]'
                : 'text-[#8B989E] hover:text-[#E8EEF0]'
            }`}
          >
            E. API Architecture
          </button>
          <button
            onClick={() => setActiveSection('boundaries')}
            className={`px-3 py-1.5 text-xs font-mono font-medium rounded transition-colors ${
              activeSection === 'boundaries'
                ? 'bg-[#2B1014] text-[#FF5B64] border border-[#FF5B64]/40 font-bold'
                : 'text-[#8B989E] hover:text-[#FF5B64]'
            }`}
          >
            F. Security Boundaries
          </button>
        </div>

        {/* Section A: System Overview */}
        {activeSection === 'overview' && (
          <div className="bg-[#0C1013] border border-[#222B30] rounded-lg p-5 space-y-4 text-xs">
            <h3 className="text-sm font-bold text-[#E8EEF0] flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#39E58C]" />
              A. SYSTEM OVERVIEW & CORE VERIFICATION PHILOSOPHY
            </h3>
            <p className="text-[#8B989E] font-sans leading-relaxed">
              Moriarty is an adaptive, invariant-driven security verification workstation engineered to resolve the fundamental
              flaw of security verification: <strong>assuming a security patch is effective because static linters or fixed tests passed.</strong>
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
              <div className="bg-[#07090B] p-3.5 rounded border border-[#222B30] space-y-2">
                <span className="text-[#38BDF8] font-bold block">1. Generalized SQLite & Python</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Evaluates arbitrary SQLite queries (SELECT, INSERT, UPDATE, DELETE, DDL, CTEs, JOINs, PRAGMAs) and Python sqlite3 code
                  without hardcoded table names, column names, or fixed scenario templates.
                </p>
              </div>
              <div className="bg-[#07090B] p-3.5 rounded border border-[#222B30] space-y-2">
                <span className="text-[#C084FC] font-bold block">2. Advisory ML Prioritization</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Independent TF-IDF character n-gram + Logistic Regression classifier scores vulnerability risk and guides probe selection
                  without possessing the authority to mark a patch verified.
                </p>
              </div>
              <div className="bg-[#07090B] p-3.5 rounded border border-[#222B30] space-y-2">
                <span className="text-[#39E58C] font-bold block">3. Empirical Differential Proof</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Executes controlled differential tests against isolated in-memory SQLite targets. Requires proof of baseline exploitability,
                  patch neutralization, and preserved benign functionality before certifying fixes.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Section B: Backend Architecture */}
        {activeSection === 'backend' && (
          <div className="bg-[#0C1013] border border-[#222B30] rounded-lg p-5 space-y-4 text-xs">
            <h3 className="text-sm font-bold text-[#E8EEF0] flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#38BDF8]" />
              B. BACKEND ARCHITECTURE & MODULE MATRIX
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono">
                <thead>
                  <tr className="border-b border-[#222B30] text-[#536168] text-[11px]">
                    <th className="pb-2">MODULE / FILE</th>
                    <th className="pb-2">PRIMARY CLASS / SYMBOL</th>
                    <th className="pb-2">RESPONSIBILITIES</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#222B30]/40 text-[11px]">
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.analysis.sqlite_parser</td>
                    <td className="text-[#E8EEF0]">SQLiteParser</td>
                    <td className="text-[#8B989E]">Native SQLite EXPLAIN syntax validation, statement classification, table/column extraction, mock schema synthesis</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.analyzer.ast_analyzer</td>
                    <td className="text-[#E8EEF0]">SQLInjectionAnalyzer</td>
                    <td className="text-[#8B989E]">Python AST traversal, multi-hop variable taint tracking, dynamic query detection (f-strings, %, .format())</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.ml.ml_analyzer</td>
                    <td className="text-[#E8EEF0]">SQLInjectionMLAnalyzer</td>
                    <td className="text-[#8B989E]">Character n-gram TF-IDF vectorizer + Logistic Regression model inference with calibrated probability estimation</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.patching.generator</td>
                    <td className="text-[#E8EEF0]">SQLPatchGenerator</td>
                    <td className="text-[#8B989E]">Deterministic AST parameterization, candidate diff generation, bounded patch refinement loop (max 3 attempts)</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.agent.planner</td>
                    <td className="text-[#E8EEF0]">AgentPlanner</td>
                    <td className="text-[#8B989E]">ML-guided adaptive test selection, explainable decision traces, planner benchmarking (compare_planners)</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.execution.local_app_runner</td>
                    <td className="text-[#E8EEF0]">LocalAppVerificationRunner</td>
                    <td className="text-[#8B989E]">Dynamic execution against isolated in-memory SQLite sandbox, semantic exploitability and parameter boundary checks</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.execution.source_executor</td>
                    <td className="text-[#E8EEF0]">ControlledSourceExecutor, SourceBoundUserApp</td>
                    <td className="text-[#8B989E]">Restricted namespace Python execution, dynamic table seeding, SHA-256 target provenance verification</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.verification.evidence_ledger</td>
                    <td className="text-[#E8EEF0]">EvidenceLedger</td>
                    <td className="text-[#8B989E]">Tamper-evident empirical evidence recording, coverage tracking, anti-forgery verification invariants</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 text-[#38BDF8]">app.verification.verdict_engine</td>
                    <td className="text-[#E8EEF0]">VerdictEngine</td>
                    <td className="text-[#8B989E]">Three-verdict evaluation logic (VERIFIED / REJECTED / INCONCLUSIVE) with honest uncertainty preservation</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Section C: Frontend Architecture */}
        {activeSection === 'frontend' && (
          <div className="bg-[#0C1013] border border-[#222B30] rounded-lg p-5 space-y-4 text-xs">
            <h3 className="text-sm font-bold text-[#E8EEF0] flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#C084FC]" />
              C. FRONTEND WORKSPACES & SPECIALIZED COMPONENTS
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-[#07090B] p-3.5 rounded border border-[#222B30] space-y-1.5">
                <span className="text-xs font-bold text-[#E8EEF0]">SQL Security Lab (Continuous Workbench)</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Dual-editor workspace for arbitrary raw SQL and Python source code. Supports debounced continuous evaluation,
                  instant AST parameterization, patch refinement, and dynamic differential verification.
                </p>
              </div>
              <div className="bg-[#07090B] p-3.5 rounded border border-[#222B30] space-y-1.5">
                <span className="text-xs font-bold text-[#818CF8]">ML Security Analysis Bar</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Side-by-side risk comparison badge showing original code risk, candidate patch risk, risk reduction delta (-88%),
                  detected syntactic features, and model version.
                </p>
              </div>
              <div className="bg-[#07090B] p-3.5 rounded border border-[#222B30] space-y-1.5">
                <span className="text-xs font-bold text-[#C084FC]">Patch Refinement Drawer</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Bounded refinement stepper showing attempt candidates #1, #2, #3, unresolved flaw extraction,
                  independent ML risk scores, and one-click application to the patch editor.
                </p>
              </div>
              <div className="bg-[#07090B] p-3.5 rounded border border-[#222B30] space-y-1.5">
                <span className="text-xs font-bold text-[#38BDF8]">Planner Benchmark Modal</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Empirical side-by-side comparison modal benchmarking Rule-Based vs ML-Guided planners on identical scenarios,
                  measuring execution time (ms), test counts, and category coverage.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Section D: Data Flow */}
        {activeSection === 'dataflow' && (
          <div className="bg-[#0C1013] border border-[#222B30] rounded-lg p-5 space-y-4 text-xs font-mono">
            <h3 className="text-sm font-bold text-[#E8EEF0] flex items-center gap-2">
              <Network className="w-4 h-4 text-[#FFBE55]" />
              D. DATA FLOW LIFECYCLE & VERIFICATION PIPELINE
            </h3>
            <ol className="space-y-3">
              <li className="p-3 rounded bg-[#07090B] border border-[#222B30]">
                <strong className="text-[#39E58C]">1. Input Submission & Language Classification:</strong>
                <span className="text-[#8B989E] block mt-0.5">
                  User inputs raw SQL statement or Python function. System detects language and routes to SQLiteParser or Python AST visitor.
                </span>
              </li>
              <li className="p-3 rounded bg-[#07090B] border border-[#222B30]">
                <strong className="text-[#38BDF8]">2. Schema Extraction & In-Memory Mock Provisioning:</strong>
                <span className="text-[#8B989E] block mt-0.5">
                  SQLiteParser extracts referenced tables and columns. Synthesizes in-memory mock SQLite schema with sample seed rows.
                </span>
              </li>
              <li className="p-3 rounded bg-[#07090B] border border-[#222B30]">
                <strong className="text-[#C084FC]">3. Independent ML Risk Scoring & Feature Extraction:</strong>
                <span className="text-[#8B989E] block mt-0.5">
                  SQLInjectionMLAnalyzer vectorizes code into character n-grams and computes posterior probability risk score [0.0 - 1.0].
                </span>
              </li>
              <li className="p-3 rounded bg-[#07090B] border border-[#222B30]">
                <strong className="text-[#818CF8]">4. Patch Generation & Bounded Refinement (Decoupled):</strong>
                <span className="text-[#8B989E] block mt-0.5">
                  AST Patch Generator rewrites query into parameter placeholders. Refinement loop re-scores each candidate up to 3 bounded attempts.
                </span>
              </li>
              <li className="p-3 rounded bg-[#07090B] border border-[#222B30]">
                <strong className="text-[#39E58C]">5. Adaptive Probe Planning & Differential Testing:</strong>
                <span className="text-[#8B989E] block mt-0.5">
                  AgentPlanner sequences targeted test probes against isolated in-memory SQLite sandbox, proving baseline exploitability and patch neutralization.
                </span>
              </li>
              <li className="p-3 rounded bg-[#07090B] border border-[#222B30]">
                <strong className="text-[#E8EEF0]">6. Provenance Validation & Verdict Formulation:</strong>
                <span className="text-[#8B989E] block mt-0.5">
                  EvidenceLedger validates cryptographic SHA-256 target provenance. VerdictEngine evaluates requirements and produces final formal verdict.
                </span>
              </li>
            </ol>
          </div>
        )}

        {/* Section E: API Architecture */}
        {activeSection === 'api' && (
          <div className="bg-[#0C1013] border border-[#222B30] rounded-lg p-5 space-y-4 text-xs font-mono">
            <h3 className="text-sm font-bold text-[#E8EEF0] flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#39E58C]" />
              E. REST API ENDPOINT DIRECTORY
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-[#222B30] text-[#536168] text-[11px]">
                    <th className="pb-2">METHOD & PATH</th>
                    <th className="pb-2">REQUEST PAYLOAD</th>
                    <th className="pb-2">RESPONSE / PURPOSE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#222B30]/40 text-[11px]">
                  <tr>
                    <td className="py-2 text-[#39E58C]">GET /api/health</td>
                    <td className="text-[#8B989E]">None</td>
                    <td className="text-[#E8EEF0]">Backend service status, version, and SQLite sandbox health</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[#38BDF8]">POST /api/lab/analyze</td>
                    <td className="text-[#8B989E]">&#123; input_text, input_type &#125;</td>
                    <td className="text-[#E8EEF0]">Generalized SQL & Python analysis with ML risk classification</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[#C084FC]">POST /api/lab/generate-patch</td>
                    <td className="text-[#8B989E]">&#123; input_text, param_name &#125;</td>
                    <td className="text-[#E8EEF0]">AST parameterization, line diffs, and remediation rationale</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[#C084FC]">POST /api/lab/refine-patch</td>
                    <td className="text-[#8B989E]">&#123; original_source, current_patch, max_attempts &#125;</td>
                    <td className="text-[#E8EEF0]">Bounded patch refinement loop with candidate history and ML scores</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[#38BDF8]">POST /api/lab/compare-planners</td>
                    <td className="text-[#8B989E]">&#123; scenario, original_source, patched_source &#125;</td>
                    <td className="text-[#E8EEF0]">Rule-based vs ML-guided planner benchmark comparison</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[#39E58C]">POST /api/lab/verify-patch</td>
                    <td className="text-[#8B989E]">&#123; original_source, candidate_patch, max_tests &#125;</td>
                    <td className="text-[#E8EEF0]">Differential verification loop with coverage and evidence ledger</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[#39E58C]">POST /api/verify</td>
                    <td className="text-[#8B989E]">&#123; original_source, patched_source, max_tests &#125;</td>
                    <td className="text-[#E8EEF0]">Primary Moriarty agent loop with provenance verification</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[#8B989E]">GET /api/catalog</td>
                    <td className="text-[#8B989E]">None</td>
                    <td className="text-[#E8EEF0]">Complete 40-test attack catalog across 12 categories</td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[#8B989E]">GET /api/reports</td>
                    <td className="text-[#8B989E]">None</td>
                    <td className="text-[#E8EEF0]">Audit reports directory and historical run summaries</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Section F: Security Boundaries */}
        {activeSection === 'boundaries' && (
          <div className="bg-[#2B1014]/40 border border-[#FF5B64]/40 rounded-lg p-5 space-y-4 text-xs font-mono">
            <h3 className="text-sm font-bold text-[#FF5B64] flex items-center gap-2">
              <Lock className="w-4 h-4" />
              F. FORMAL SECURITY BOUNDARIES & INTEGRITY GUARANTEES
            </h3>
            <div className="space-y-3 text-[#E8EEF0] leading-relaxed">
              <div className="p-3 rounded bg-[#07090B] border border-[#FF5B64]/30 space-y-1">
                <span className="text-[#FF5B64] font-bold block">1. The ML Model is Advisory (Never Authoritative):</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  The TF-IDF and Logistic Regression pipeline provides heuristic risk scores and test prioritization hints.
                  The ML model cannot independently declare a vulnerability verified, and a patch is NEVER marked VERIFIED
                  solely because its ML risk score decreased.
                </p>
              </div>

              <div className="p-3 rounded bg-[#07090B] border border-[#FF5B64]/30 space-y-1">
                <span className="text-[#FF5B64] font-bold block">2. Decoupled Patch Generation:</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  The patch generator creates candidate AST rewrites with is_verified = False. The patch generator does not
                  score its own patches; candidate patches are independently evaluated by the ML inference engine and tested
                  against isolated dynamic targets.
                </p>
              </div>

              <div className="p-3 rounded bg-[#07090B] border border-[#FF5B64]/30 space-y-1">
                <span className="text-[#FF5B64] font-bold block">3. Driver Restrictions & Honest Uncertainty:</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Python’s default sqlite3 driver restricts multi-statement execution. Stacked query tests (SQLI_STACK_001-003)
                  are tracked as not_applicable rather than false passes. Broken functionality, runtime errors, or provenance
                  mismatches strictly preserve INCONCLUSIVE.
                </p>
              </div>

              <div className="p-3 rounded bg-[#07090B] border border-[#FF5B64]/30 space-y-1">
                <span className="text-[#FF5B64] font-bold block">4. Scope of Verification:</span>
                <p className="text-[11px] text-[#8B989E] font-sans">
                  Moriarty proves that untrusted input cannot escape parameter boundaries on the targeted SQLite query construction path.
                  It does not claim application-wide absence of other unrelated vulnerabilities.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
