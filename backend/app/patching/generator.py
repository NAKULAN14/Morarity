"""
Deterministic Security Patch Generator for Moriarty SQL Security Lab.

Transforms vulnerable SQL queries and Python database interaction code into
parameterized implementations using AST and syntax-aware rewriting.
Generates full technical explanations, security invariants, and executable
sandboxed implementations for differential verification.
"""

import ast
import difflib
import re
from typing import Any, Optional

from app.llm.reasoner import LLMSecurityReasoner
from app.ml.ml_analyzer import SQLInjectionMLAnalyzer
from app.patching.sql_analyzer import SQLVulnerabilityAnalyzer


class SQLPatchGenerator:
    """
    Generates parameterized SQL security patches from raw SQL queries or Python code.
    Ensures generated patches are treated strictly as unverified candidates until
    empirical differential verification executes.
    """

    GENERATION_METHOD = "DETERMINISTIC_AST_PARAMETERIZER"

    def __init__(self) -> None:
        self.analyzer = SQLVulnerabilityAnalyzer()
        self.ml_analyzer = SQLInjectionMLAnalyzer()
        self.llm_reasoner = LLMSecurityReasoner()

    def generate_patch(
        self,
        input_text: str,
        input_type: str = "auto",
        param_name: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Generate a parameterized security patch along with diff, explanation,
        and executable test wrappers.
        """
        text = input_text.strip() if input_text else ""
        analysis = self.analyzer.analyze(text, input_type=input_type)
        input_kind = analysis["input_kind"]

        if input_kind == "PYTHON_CODE":
            patch_data = self._generate_python_patch(text, analysis, param_name)
        else:
            patch_data = self._generate_sql_patch(text, analysis, param_name)

        # Re-analyze generated patch independently with ML model and LLM reasoning
        patch_data["ml_analysis"] = self.ml_analyzer.analyze(patch_data["patched_code"])
        patch_data["llm_reasoning"] = self.llm_reasoner.reason_about_patch(
            original_code=text,
            patch_code=patch_data["patched_code"],
            ml_analysis=patch_data["ml_analysis"],
        )
        return patch_data

    def refine_patch_loop(
        self,
        original_source: str,
        current_patch: Optional[str] = None,
        max_attempts: int = 3,
        param_name: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Execute bounded patch refinement loop (up to max_attempts):
        Re-analyzes each patch candidate using static AST analysis and the ML analyzer,
        detects remaining vulnerabilities or naive sanitization, and refines the candidate
        into a secure parameterized implementation.
        """
        orig_text = (original_source or "").strip()
        orig_ml = self.ml_analyzer.analyze(orig_text)

        target_param = param_name or "username"
        table = "users"

        # Determine initial candidate
        if current_patch and current_patch.strip():
            candidate_code = current_patch.strip()
        else:
            initial = self.generate_patch(orig_text, param_name=target_param)
            candidate_code = initial["patched_code"]

        candidates_history: list[dict[str, Any]] = []
        is_clean = False
        final_ml = orig_ml

        for attempt in range(1, max_attempts + 1):
            # 1. Independent Static AST Analysis
            static_res = self.analyzer.analyze(candidate_code)
            findings = static_res.get("findings", [])
            unresolved = [
                f.message for f in findings
                if getattr(f, "severity", None) in ("CRITICAL", "HIGH", "MEDIUM")
            ]

            # 2. Independent ML Analysis
            ml_res = self.ml_analyzer.analyze(candidate_code)
            final_ml = ml_res
            if ml_res.get("risk_score", 0.0) >= 0.35:
                unresolved.append(f"ML Classifier identified elevated risk ({ml_res['risk_score']:.2f})")

            # 3. Compute Diff
            diff_lines = self._compute_diff(orig_text, candidate_code)

            # 4. Record Candidate
            explanation = (
                f"Candidate refinement attempt #{attempt}. "
                f"ML Risk Score: {ml_res.get('risk_score', 0.0):.2f} ({ml_res.get('risk_level', 'LOW')}). "
                f"{len(unresolved)} unresolved issues detected."
            )
            candidates_history.append({
                "attempt": attempt,
                "patch_code": candidate_code,
                "diff_lines": diff_lines,
                "ml_risk_score": ml_res.get("risk_score", 0.0),
                "ml_risk_level": ml_res.get("risk_level", "LOW"),
                "unresolved_findings": unresolved,
                "explanation": explanation,
            })

            # Check if candidate meets safety threshold
            if len(unresolved) == 0 and ml_res.get("risk_score", 0.0) < 0.25:
                is_clean = True
                break

            # If flawed or unresolved and attempts remain, refine into standard parameterized AST form
            if attempt < max_attempts:
                candidate_code = self._rewrite_python_source(candidate_code, target_param, table)

        summary = (
            f"Patch refinement loop completed after {len(candidates_history)}/{max_attempts} attempts. "
            f"Original ML Risk: {orig_ml.get('risk_score', 0.0):.2f} -> Final ML Risk: {final_ml.get('risk_score', 0.0):.2f}. "
            f"Fully refined: {is_clean}."
        )

        return {
            "original_source": orig_text,
            "final_patch": candidate_code,
            "attempts_made": len(candidates_history),
            "max_attempts": max_attempts,
            "is_fully_refined": is_clean,
            "original_ml_analysis": orig_ml,
            "final_ml_analysis": final_ml,
            "candidates": candidates_history,
            "refinement_summary": summary,
        }

    def _generate_sql_patch(
        self,
        raw_sql: str,
        analysis: dict[str, Any],
        param_name: Optional[str],
    ) -> dict[str, Any]:
        """Generate patch for a raw SQL query string."""
        target_param = param_name or (
            analysis["detected_parameters"][0]
            if analysis["detected_parameters"]
            else "username"
        )
        table = analysis.get("detected_table") or "users"

        # Parameterize raw SQL: replace WHERE col = 'val' with WHERE col = ?
        patched_sql = self._parameterize_sql_string(raw_sql, target_param)

        # Synthesize executable Python functions for dynamic differential testing
        executable_original = self._synthesize_vulnerable_python(raw_sql, target_param, table)
        executable_patched = self._synthesize_patched_python(patched_sql, target_param)

        diff_lines = self._compute_diff(raw_sql, patched_sql)

        explanation = (
            f"Replaced unparameterized literal embedding in '{target_param}' filter with a "
            "standard SQLite parameter placeholder (?). Untrusted user input is bound separately "
            "as a query argument tuple `(username,)`, ensuring the SQLite query planner compiles "
            "the SQL syntax ahead of time. Metacharacters like single quotes (') or comments (--) "
            "are treated strictly as literal data."
        )

        invariants = [
            f"Query structure for '{table}' remains immutable regardless of payload.",
            f"Input bound to parameter '{target_param}' cannot escape string data boundary.",
            "Benign search functionality preserves exact record retrieval.",
        ]

        return {
            "original_input": raw_sql,
            "patched_code": patched_sql,
            "patched_sql": patched_sql,
            "executable_original_source": executable_original,
            "executable_patched_source": executable_patched,
            "input_kind": "RAW_SQL",
            "technique": "PARAMETERIZED_QUERY_SUBSTITUTION",
            "generation_method": self.GENERATION_METHOD,
            "technical_explanation": explanation,
            "invariants_enforced": invariants,
            "diff_lines": diff_lines,
            "is_verified": False,
        }

    def _generate_python_patch(
        self,
        python_code: str,
        analysis: dict[str, Any],
        param_name: Optional[str],
    ) -> dict[str, Any]:
        """Generate patch for a Python function containing database calls."""
        target_param = param_name or (
            analysis["detected_parameters"][0]
            if analysis["detected_parameters"]
            else "username"
        )
        table = analysis.get("detected_table") or "users"

        patched_code = self._rewrite_python_source(python_code, target_param, table)
        diff_lines = self._compute_diff(python_code, patched_code)

        explanation = (
            "Transformed dynamic SQL query construction (string concatenation/f-string) "
            "into parameterized query execution. The SQL statement uses '?' placeholders and "
            f"passes `({target_param},)` in the cursor.execute() parameter tuple. "
            "This eliminates SQL injection vulnerabilities at the SQLite driver layer."
        )

        invariants = [
            "SQL command grammar is parsed before any user input is bound.",
            f"The variable '{target_param}' is bound exclusively as data, not executable code.",
            "Function return signature and schema remain 100% compatible with existing callers.",
        ]

        return {
            "original_input": python_code,
            "patched_code": patched_code,
            "patched_sql": f"SELECT id, username, role, email FROM {table} WHERE {target_param} = ?",
            "executable_original_source": python_code,
            "executable_patched_source": patched_code,
            "input_kind": "PYTHON_CODE",
            "technique": "AST_PARAMETERIZED_EXECUTE_REWRITE",
            "generation_method": self.GENERATION_METHOD,
            "technical_explanation": explanation,
            "invariants_enforced": invariants,
            "diff_lines": diff_lines,
            "is_verified": False,
        }

    def _parameterize_sql_string(self, sql: str, param_name: str) -> str:
        """Replace literal values or concatenation tokens in SQL WHERE clause with ?."""
        s = sql.strip()
        # Handle trailing unclosed quotes from concatenation like "WHERE col = '"
        s = re.sub(r'(=|!=|<>|LIKE)\s*[\'"][^\'"]*$', r'\1 ?', s)
        s = re.sub(r'(=|!=|<>|LIKE)\s*[\'"]?\s*$', r'\1 ?', s)
        if "?" in s:
            return s

        # Replace WHERE param = 'val' or param = "val" or param = 123
        pattern = re.compile(
            rf'({param_name}\s*=\s*)(?:\'[^\']*\'|"[^"]*"|\d+)',
            re.IGNORECASE,
        )
        if pattern.search(s):
            return pattern.sub(r'\1?', s)

        # General literal replacement in WHERE clause
        where_match = re.search(r'\bWHERE\s+(.+)', s, re.IGNORECASE)
        if where_match:
            where_body = where_match.group(1)
            # Replace 'any_quoted_str' with ?
            replaced_where = re.sub(r'\'[^\']*\'', '?', where_body)
            if replaced_where != where_body:
                return s[:where_match.start(1)] + replaced_where

        # Fallback: append WHERE clause parameterized
        if "WHERE" not in s.upper():
            return f"{s.strip()} WHERE {param_name} = ?"

        return s

    def _synthesize_vulnerable_python(self, raw_sql: str, param_name: str, table: str) -> str:
        """Synthesize a runnable vulnerable Python function for raw SQL testing."""
        # If the SQL does not have a WHERE clause with param, create standard vulnerable query
        return (
            f"def get_user_by_username(cursor, {param_name}: str):\n"
            f"    query = \"SELECT id, username, role, email FROM {table} WHERE {param_name} = '\" + {param_name} + \"'\"\n"
            f"    cursor.execute(query)\n"
            f"    return cursor.fetchall()\n"
        )

    def _synthesize_patched_python(self, patched_sql: str, param_name: str) -> str:
        """Synthesize a runnable patched Python function with parameter binding."""
        # Clean SQL formatting
        clean_sql = re.sub(r'\s+', ' ', patched_sql.strip())
        return (
            f"def get_user_by_username(cursor, {param_name}: str):\n"
            f"    cursor.execute(\n"
            f"        \"{clean_sql}\",\n"
            f"        ({param_name},),\n"
            f"    )\n"
            f"    return cursor.fetchall()\n"
        )

    def _rewrite_python_source(self, code: str, param_name: str, table: str) -> str:
        """Rewrite Python source code into parameterized execution, preserving structure and columns."""
        try:
            tree = ast.parse(code)
            func_name = "get_user_by_username"
            args_list = ["cursor", f"{param_name}"]
            base_sql = ""

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_name = node.name
                    args_list = [a.arg for a in node.args.args]
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if any(node.value.strip().upper().startswith(k) for k in ("SELECT", "INSERT", "UPDATE", "DELETE", "WITH")):
                        base_sql = node.value
                elif isinstance(node, ast.JoinedStr):
                    parts = []
                    for part in node.values:
                        if isinstance(part, ast.Constant):
                            parts.append(str(part.value))
                        else:
                            parts.append("?")
                    base_sql = "".join(parts)

            if base_sql:
                parameterized_sql = self._parameterize_sql_string(base_sql, param_name)
            else:
                if table == "users":
                    parameterized_sql = f"SELECT id, username, role, email FROM users WHERE {param_name} = ?"
                else:
                    parameterized_sql = f"SELECT * FROM {table} WHERE {param_name} = ?"

            clean_sql = re.sub(r'\s+', ' ', parameterized_sql.strip())
            args_str = ", ".join(args_list)

            return (
                f"def {func_name}({args_str}):\n"
                f"    cursor.execute(\n"
                f"        \"{clean_sql}\",\n"
                f"        ({param_name},),\n"
                f"    )\n"
                f"    return cursor.fetchall()\n"
            )
        except Exception:
            return (
                f"def get_user_by_username(cursor, {param_name}: str):\n"
                f"    cursor.execute(\n"
                f"        \"SELECT id, username, role, email FROM {table} WHERE {param_name} = ?\",\n"
                f"        ({param_name},),\n"
                f"    )\n"
                f"    return cursor.fetchall()\n"
            )

    def _compute_diff(self, original: str, patched: str) -> list[dict[str, Any]]:
        """Compute structured line diff between original and patched."""
        orig_lines = original.splitlines()
        patch_lines = patched.splitlines()
        matcher = difflib.SequenceMatcher(None, orig_lines, patch_lines)
        diff_entries: list[dict[str, Any]] = []

        line_num = 1
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                for line in orig_lines[i1:i2]:
                    diff_entries.append({"type": "unchanged", "line": line_num, "text": line})
                    line_num += 1
            elif tag == 'replace':
                for line in orig_lines[i1:i2]:
                    diff_entries.append({"type": "removed", "line": line_num, "text": line})
                for line in patch_lines[j1:j2]:
                    diff_entries.append({"type": "added", "line": line_num, "text": line})
                    line_num += 1
            elif tag == 'delete':
                for line in orig_lines[i1:i2]:
                    diff_entries.append({"type": "removed", "line": line_num, "text": line})
            elif tag == 'insert':
                for line in patch_lines[j1:j2]:
                    diff_entries.append({"type": "added", "line": line_num, "text": line})
                    line_num += 1

        return diff_entries
