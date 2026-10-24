# Moriarty Architecture

Moriarty operates as an adaptive, multi-stage security verification agent.

## Core Pipelines

1. **Static AST Analysis Stage**
   - Source code is parsed via Python `ast`.
   - `SQLInjectionAnalyzer` identifies SQL execution calls (`cursor.execute`, `executemany`).
   - Categorizes query construction:
     - `SQLI_UNSAFE_QUERY`: String concatenation or string formatting.
     - `SQLI_PARAMETERIZED_QUERY`: Query parameters passed separately.
     - `SQLI_STATIC_QUERY`: Static string literals.
     - `SQLI_UNKNOWN_QUERY`: Unclassified call expressions.

2. **Patch Comparison Stage**
   - `PatchComparator` compares original and patched AST findings.
   - Computes:
     - `PATCH_PATTERN_IMPROVED`: Baseline unsafe query replaced with parameterized/static query.
     - `VULNERABILITY_REMAINS`: Unsafe query construction still present in patch.
     - `BASELINE_NOT_DETECTED`: Original code lacked recognized unsafe pattern.
     - `INCONCLUSIVE`: Ambiguous structures or unknown queries.
     - `ANALYSIS_UNSUPPORTED`: Syntax error in either version.

3. **Finding-Aware Agent Planner**
   - Uses analyzer findings and patch status to select strategies.
   - Explains:
     - Evidence used (findings, status, past results).
     - Reason for action.
     - Expected learning.
     - Stop condition.
   - Adapts to observation feedback.

4. **Dynamic Execution & Evidence Collection**
   - `LocalAppVerificationRunner` sends controlled inputs to target applications.
   - Distinguishes:
     - `REAL_APPLICATION_VERIFICATION` (runs against actual local SQLite app instances).
     - `CONTROLLED_DEMONSTRATION` (simulated in-memory fixtures).
   - Verifies baseline exploitability, patch resistance, and functionality preservation.

5. **Verdict Engine**
   - Preserves three outcomes: `VERIFIED`, `REJECTED`, `INCONCLUSIVE`.
   - Enforces honesty: controlled fixtures alone can never produce `VERIFIED`.
   - Produces structured JSON reports and audit trails.
