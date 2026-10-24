# Moriarty — Structural Security Patch Verification

> *"An adaptive security verification agent that tries to disprove the claim that a vulnerability has been fixed before allowing that claim to be marked VERIFIED."*

---

## 1. Project Objective

Automated security patches and static code reviews frequently suffer from a false sense of security. Static analysis tools can recognize surface-level patterns, and naive unit tests often pass even when the underlying vulnerability remains exploitable.

**Moriarty** is an adaptive, observation-driven security verification agent focused on structural security patch auditing. Rather than blindly trusting a patch or relying on static heuristics, Moriarty:
1. Performs AST-based structural analysis of both vulnerable and patched source code.
2. Formulates a finding-aware verification plan based on detected AST rules (`SQLI_UNSAFE_QUERY`, `SQLI_PARAMETERIZED_QUERY`, `SQLI_STATIC_QUERY`, `SQLI_UNKNOWN_QUERY`).
3. Enforces an explicit and auditable relationship between submitted source code and runtime targets (preventing source/target mismatch).
4. Executes controlled, non-destructive payloads against either safely compiled submitted source in an isolated namespace or registered local applications with verified provenance.
5. Evaluates genuine SQL injection semantics (rejecting row-count-only heuristics, checking parameter separation, and enforcing configurable functionality invariants).
6. Gathers empirical runtime observations into an evidence ledger.
7. Enforces a strict, explainable 3-outcome verdict model (`VERIFIED`, `REJECTED`, `INCONCLUSIVE`) with consistent final actions and stopping reasons.

---

## 2. Architecture & Provenance Verification

```
                      +-----------------------------+
                      |   Vulnerable Source Code    |
                      |    Patched Source Code      |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   AST Code & Rule Analyzer  |
                      |   (SQLInjectionAnalyzer)    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |      Patch Comparator       |
                      |  (Original vs Patch Rules)  |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      | Source-to-Runtime Provenance|
                      |   Validator & Executor      |
                      |  (Matches Source -> Target) |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      | Finding-Aware Agent Planner | <---+
                      | (Action, Strategy, Reason)  |     |
                      +--------------+--------------+     |
                                     |                    |
                                     v                    |
                      +-----------------------------+     | (Observation
                      | Local App Verification      |     |  Feedback)
                      | Runner (SQLite Target App)  |     |
                      +--------------+--------------+     |
                                     |                    |
                                     v                    |
                      +-----------------------------+     |
                      |       Evidence Ledger       | ----+
                      | (Validated Observations)    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |       Verdict Engine        |
                      | VERIFIED/REJECTED/INCONCL.  |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      | Structured JSON Report &    |
                      | Complete Decision Trace     |
                      +-----------------------------+
```

### Core Components:
- **`app.analyzer.ast_analyzer`**: Python AST parser identifying query construction patterns (`SQLI_UNSAFE_QUERY`, `SQLI_PARAMETERIZED_QUERY`, `SQLI_STATIC_QUERY`, `SQLI_UNKNOWN_QUERY`).
- **`app.verification.patch_comparator`**: Compares original and patched AST findings without executing code (`PATCH_PATTERN_IMPROVED`, `VULNERABILITY_REMAINS`, `BASELINE_NOT_DETECTED`, `INCONCLUSIVE`, `ANALYSIS_UNSUPPORTED`).
- **`app.execution.source_executor`**: Validates submitted source AST against strict restrictions (disallowing imports, filesystem/network access, and dangerous builtins) and executes it against an in-memory SQLite database, or verifies provenance correspondence for registered applications.
- **`app.agent.planner`**: Observation-driven and finding-aware agent planner that adapts payloads based on runtime observations and static signals, producing consistent stopping reasons (`VERIFICATION_REQUIREMENTS_SATISFIED`, `VULNERABILITY_REMAINS_EXPLOITABLE`, `TEST_BUDGET_EXHAUSTED_WITHOUT_SUFFICIENT_EVIDENCE`).
- **`app.execution.local_app_runner`**: Executes controlled tests against local SQLite targets (`VulnerableUserApp`, `PatchedUserApp`, `IncompletePatchUserApp`, `SourceBoundUserApp`), checking actual parameterization semantics and evaluating configurable `FunctionalityInvariant`s.
- **`app.verification.evidence_ledger`**: Stores structured evidence records and categorizes them (`REAL_APPLICATION_VERIFICATION`, `CONTROLLED_DEMONSTRATION`, `STATIC_ANALYSIS`), tracking `target_provenance`, `submitted_source_executed`, and `source_runtime_match`.
- **`app.verification.verdict_engine`**: Independently validates evidence fields rather than trusting labels alone, enforcing that controlled fixtures can never produce a false `VERIFIED` verdict.
- **`app.reporting.report_generator`**: Outputs audit-ready JSON reports with full decision traces, test inputs, observations, stopping reasons, and explicit limitations.

---

## 3. What Moriarty Verifies & What It Does Not Verify

### What It Verifies
- **Targeted SQL Query Parameterization**: Verifies whether untrusted inputs to the tested query construction path are treated strictly as bound parameters rather than SQL syntax.
- **Baseline Exploitability**: Establishes whether the original query was genuinely vulnerable to the test payloads before claiming a fix.
- **Preservation of Legitimate Functionality**: Validates that benign queries continue to return the expected application records.
- **Source-to-Runtime Correspondence**: Verifies that the executed runtime implementation demonstrably matches the submitted source code.

### What It Does NOT Verify
- **Whole-Application Security**: A `VERIFIED` verdict applies strictly to the targeted query execution path. It does **not** certify that other routes, modules, or services are free from SQL injection or other vulnerabilities.
- **Arbitrary Python Sandboxing**: The controlled source executor restricts AST constructs (functions querying SQLite) but does not claim to provide a full OS-level sandbox for untrusted general-purpose Python code.
- **Universal Fix Proof**: Passing a finite test budget does not mathematically prove that no injection payload exists; it proves that the parameterized property held across the representative test strategies without altering query logic.
- **Unverified Fixtures**: Simulated fixtures or targets with mismatched source code are strictly prevented from producing a `VERIFIED` outcome.

---

## 4. Verdict Semantics & Verification Hierarchy

Moriarty strictly maintains a three-outcome model:

| Verdict | Meaning | Required Evidence |
| :--- | :--- | :--- |
| **`VERIFIED`** | The patch demonstrably eliminates the vulnerability for the tested query path while preserving required functionality. | Requires dynamic testing against a **real local application** (`REAL_APPLICATION_VERIFICATION` or `SUBMITTED_SOURCE_EXECUTION`) where: `source_runtime_match == True`, baseline was proven exploitable, patch blocked all payloads, benign lookups functioned, and static analysis showed improvement. |
| **`REJECTED`** | The vulnerability remains exploitable in the patched code path. | Dynamic test observation demonstrated that payload altered query logic or leaked unauthorized records (`patch_blocks_payload == False`), or patch failed to separate parameters. |
| **`INCONCLUSIVE`** | Verification cannot be claimed. Uncertainty is strictly preserved. | Triggered when: source/runtime provenance mismatch occurs; only static analysis is available; only controlled simulated fixtures ran; analysis is unsupported (syntax error); query structure is unknown (`SQLI_UNKNOWN_QUERY`); or testing budget ended before sufficient evidence was collected. |

---

## 5. Setup & Installation

### Requirements
- Python 3.10+ (Tested on Python 3.13)
- Windows PowerShell / Command Prompt

### Virtual Environment Setup
```powershell
# Navigate to repository root
cd c:\Users\nakul\OneDrive\Desktop\Morarity

# Activate virtual environment
.\backend\venv\Scripts\Activate.ps1

# Install requirements (if not already installed)
pip install -r requirements.txt
```

---

## 6. Commands to Run Demo & Tests

### Run the End-to-End Demo
Executes 4 comprehensive verification scenarios:
```powershell
& "backend/venv/Scripts/python.exe" demo.py
```

### Run the Complete Test Suite
Executes all 66 automated test cases (including all 18 verification integrity tests):
```powershell
& "backend/venv/Scripts/pytest.exe"
```

### Run the Differential Patch Check
```powershell
& "backend/venv/Scripts/python.exe" backend/check_patch_aware_loop.py
```

---

## 7. Example Output

### Scenario 1: Real Local SQLite Application with Valid Parameterized Patch
```text
==============================================================================
  SCENARIO 1: REAL LOCAL SQLITE APPLICATION — VALID PARAMETERIZED PATCH
==============================================================================
Target: Intentionally vulnerable local SQLite user lookup service
Expected: Agent challenges patch with controlled payloads, observes safe handling,
checks functionality preservation, and issues VERIFIED with explicit scope.

--- Static Patch Comparison ---
Status: PATCH_PATTERN_IMPROVED
Summary: The recognized unsafe SQL construction in the original source is absent from the patched source, and the patch contains a recognized static or parameterized SQL pattern.
Original findings: ['SQLI_UNSAFE_QUERY']
Patched findings: ['SQLI_PARAMETERIZED_QUERY']
Static improvement detected: True

[Agent Step 1] Action: RUN_TEST
Reason: Triggered by finding SQLI_PARAMETERIZED_QUERY in patched source... Starting with boolean-based test.
Selected Strategy: BOOLEAN_OR | Payload: ' OR '1'='1
Test outcome: PASS (Passed=True)
Baseline exploitable: True | Patch blocks: True
Functionality intact: True
Target Provenance: REGISTERED_SCENARIO_MATCH (Match=True)

[Agent Step 2] Action: RUN_TEST
Selected Strategy: BOOLEAN_COMMENT | Payload: ' OR 1=1 --
Test outcome: PASS (Passed=True)

[Agent Step 3] Action: RUN_TEST
Selected Strategy: BOOLEAN_ADMIN | Payload: admin' OR '1'='1' --
Test outcome: PASS (Passed=True)

[Agent Step 4] Action: STOP_VERIFIED
Reason: Testing budget completed (3/3 tests). All controlled verification tests against the local target succeeded.

Final Verdict: [VERIFIED]
Final Action:  [STOP_VERIFIED]
Stopping Reason: [VERIFICATION_REQUIREMENTS_SATISFIED]
Target Provenance: [REGISTERED_SCENARIO_MATCH] (Match=True)
Summary: Controlled dynamic verification demonstrated that SQL injection payloads were blocked, parameters were safely separated, and application query functionality was preserved. Verification scope: targeted local SQLite query construction path. Does not claim application-wide absence of other vulnerabilities.
```

### Scenario 2: Incomplete Patch (Naive sanitization)
```text
==============================================================================
  SCENARIO 2: REAL LOCAL SQLITE APPLICATION — INCOMPLETE PATCH
==============================================================================

[Agent Step 1] Action: RUN_TEST
Reason: Triggered by finding SQLI_UNSAFE_QUERY in patched source: unsafe SQL construction pattern remains detected.
Selected Strategy: BOOLEAN_OR | Payload: ' OR '1'='1
Test outcome: FAIL (Passed=False)
Baseline exploitable: True | Patch blocks: False
Functionality intact: True
Target Provenance: REGISTERED_SCENARIO_MATCH (Match=True)

[Agent Step 2] Action: STOP_REJECTED
Reason: The expected vulnerable-versus-patched behavior was not observed. The test payload was not safely blocked by the patched implementation. Vulnerability remains exploitable.

Final Verdict: [REJECTED]
Final Action:  [STOP_REJECTED]
Stopping Reason: [VULNERABILITY_REMAINS_EXPLOITABLE]
Summary: Evidence demonstrates that the vulnerability remains exploitable in the patched application. Test payloads altered SQL query logic or bypassed insufficient query sanitization.
```

### Scenario 3: Controlled Fixture Testing (Honesty Guardrail)
```text
==============================================================================
  SCENARIO 3: CONTROLLED FIXTURE TESTING — HONESTY ENFORCEMENT
==============================================================================
Target: Controlled in-memory demonstration without real application execution

Final Verdict: [INCONCLUSIVE]
Final Action:  [STOP_INCONCLUSIVE]
Stopping Reason: [TEST_BUDGET_EXHAUSTED_WITHOUT_SUFFICIENT_EVIDENCE]
Summary: The controlled demonstration completed, but it did not execute the submitted application. Real application dynamic verification is required to verify the patch.
```

### Scenario 4: Direct Submitted-Source Isolated Execution
```text
==============================================================================
  SCENARIO 4: DIRECT SUBMITTED-SOURCE ISOLATED EXECUTION
==============================================================================
Target: Submitted Python source safely compiled in isolated environment

Final Verdict: [VERIFIED]
Final Action:  [STOP_VERIFIED]
Target Type:   [SUBMITTED_SOURCE_EXECUTION]
Provenance:    [RESTRICTED_SOURCE_ENV] (SubmittedSourceExecuted=True)
Summary: Controlled dynamic verification demonstrated that SQL injection payloads were blocked, parameters were safely separated, and application query functionality was preserved. Verification scope: targeted local SQLite query construction path. Does not claim application-wide absence of other vulnerabilities.
```

---

## 8. Limitations & Scope

1. **Verification Scope**: Verification is strictly bounded to the specific local SQLite query execution path tested. A `VERIFIED` verdict does not claim that the wider application or untested routes are free from other security vulnerabilities.
2. **Vulnerability Focus**: The current MVP specifically analyzes and verifies SQL injection vulnerabilities. Other vulnerability classes (e.g., Command Injection, Path Traversal, SSRF) are outside the current scope.
3. **Target Scope**: Dynamic tests run exclusively against local, non-destructive test databases. Moriarty does not execute tests against arbitrary or external infrastructure.
4. **Static Analysis Bounds**: Highly obfuscated queries or dynamically generated SQL via complex multi-module ORMs may produce `SQLI_UNKNOWN_QUERY`, in which case Moriarty halts with `INCONCLUSIVE` rather than guessing.
5. **Submitted Source Execution Bounds**: Supported submitted code is restricted to self-contained Python functions executing SQLite queries. Functions attempting external imports, network connections, filesystem operations, or dynamic code execution are rejected as unsupported.
