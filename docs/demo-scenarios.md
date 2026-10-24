# Moriarty Demonstration Scenarios

## Scenario 1: Correctly Patched Application
- **Vulnerable Source**: Uses string concatenation to build SQL query.
- **Patched Source**: Uses parameterization `(username,)`.
- **Target**: `PatchedUserApp` (local SQLite database with user records).
- **Agent Behavior**:
  1. Identifies `SQLI_PARAMETERIZED_QUERY`.
  2. Plans challenges: `BOOLEAN_OR`, `BOOLEAN_COMMENT`, `BOOLEAN_ADMIN`.
  3. Executes payloads: baseline leaks rows, patch neutralizes them, functionality intact.
  4. Final Verdict: **`VERIFIED`** (Explicit Scope: targeted SQLite user search query path).

## Scenario 2: Incomplete Patch (Bypass Discovery)
- **Vulnerable Source**: Unsafe concatenation.
- **Patched Source**: Naive sanitization (`replace("--", "")`).
- **Target**: `IncompletePatchUserApp`.
- **Agent Behavior**:
  1. Identifies `SQLI_UNSAFE_QUERY` still present.
  2. Tests `BOOLEAN_OR` payload (`' OR '1'='1`).
  3. Observes 3 rows returned by patched app -> patch failed to block exploit.
  4. Stops investigation immediately.
  5. Final Verdict: **`REJECTED`**.

## Scenario 3: Controlled Fixture (Honesty Guardrail)
- **Target**: Simulated differential fixture only.
- **Agent Behavior**:
  1. Tests succeed against simulated fixture.
  2. Agent and Verdict Engine recognize that no real application was executed.
  3. Refuses false safety claim.
  4. Final Verdict: **`INCONCLUSIVE`**.
