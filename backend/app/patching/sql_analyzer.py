"""
SQL Vulnerability Analyzer for Moriarty SQL Security Lab.

Analyzes raw SQL queries and SQL-related Python source code to detect
SQL injection risks, extract targets/parameters, and define security invariants.
"""

import ast
import re
from typing import Any, Optional

from app.analysis.sqlite_parser import SQLiteParser, SQLiteStatementType
from app.analyzer.ast_analyzer import SQLInjectionAnalyzer
from app.catalog.sql_catalog import get_catalog, get_executable_tests
from app.llm.reasoner import LLMSecurityReasoner
from app.ml.ml_analyzer import SQLInjectionMLAnalyzer
from app.models.schemas import (
    AnalysisFinding,
    FindingSeverity,
)


class SQLVulnerabilityAnalyzer:
    """
    Dual-mode analyzer for raw SQL queries and Python database interaction code.
    Identifies dynamic query construction, unparameterized literals, and extracts query structure.
    """

    TABLE_REGEX = re.compile(
        r'\b(?:FROM|INTO|UPDATE|TABLE)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
        re.IGNORECASE,
    )

    WHERE_CLAUSE_REGEX = re.compile(
        r'\bWHERE\s+(.+?)(?:\s+(?:GROUP\s+BY|HAVING|ORDER\s+BY|LIMIT)\b|$)',
        re.IGNORECASE | re.DOTALL,
    )

    COL_LITERAL_REGEX = re.compile(
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(=|!=|<>|LIKE)\s*(\'([^\']*)\'|"([^"]*)"|(\d+))',
        re.IGNORECASE,
    )

    PROBE_PAYLOADS = [
        t.payload for t in get_catalog()
        if t.execution_support == "SUPPORTED" and not t.is_benign
    ][:10]

    def __init__(self) -> None:
        self.python_analyzer = SQLInjectionAnalyzer()
        self.ml_analyzer = SQLInjectionMLAnalyzer()
        self.llm_reasoner = LLMSecurityReasoner()

    def is_python(self, text: str) -> bool:
        """Heuristic check to determine if input text is Python source code or raw SQL."""
        trimmed = text.strip()
        if not trimmed:
            return False
        if trimmed.startswith("def ") or "cursor.execute" in trimmed or "import " in trimmed or "return " in trimmed:
            return True
        try:
            tree = ast.parse(trimmed)
            # If it parses and contains function defs or assignments with cursor calls
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Import, ast.ImportFrom)):
                    return True
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("execute", "executemany"):
                        return True
        except SyntaxError:
            pass
        return False

    def analyze(self, input_text: str, input_type: str = "auto") -> dict[str, Any]:
        """
        Analyze either raw SQL or Python code for SQL injection vulnerabilities.
        """
        text = input_text.strip() if input_text else ""
        if not text:
            return {
                "input_kind": "EMPTY",
                "is_vulnerable": False,
                "vulnerability_type": None,
                "severity": FindingSeverity.INFO,
                "confidence": "HIGH",
                "detected_table": None,
                "detected_parameters": [],
                "findings": [
                    AnalysisFinding(
                        rule_id="INPUT_EMPTY",
                        message="Input is empty. Provide raw SQL or Python database code.",
                        severity=FindingSeverity.INFO,
                    )
                ],
                "security_invariants": [],
                "potential_payloads": [],
                "summary": "No input provided for analysis.",
            }

        determine_as_python = (input_type == "python") or (input_type == "auto" and self.is_python(text))

        if determine_as_python:
            result = self._analyze_python(text)
        else:
            result = self._analyze_raw_sql(text)

        result["ml_analysis"] = self.ml_analyzer.analyze(text)
        result["llm_reasoning"] = self.llm_reasoner.reason_about_source(
            text,
            input_type="python" if determine_as_python else "raw_sql",
            ast_findings=result.get("findings", []),
            ml_analysis=result["ml_analysis"],
        )
        return result

    def _analyze_python(self, source_code: str) -> dict[str, Any]:
        """Analyze Python source code using AST."""
        ast_result = self.python_analyzer.analyze(source_code)

        has_unsafe = any(f.rule_id == "SQLI_UNSAFE_QUERY" for f in ast_result.findings)
        has_parameterized = any(f.rule_id == "SQLI_PARAMETERIZED_QUERY" for f in ast_result.findings)
        has_syntax_err = any(f.rule_id == "PYTHON_SYNTAX_ERROR" for f in ast_result.findings)

        # Extract table and parameters from AST if possible
        tables: list[str] = []
        parameters: list[str] = []
        try:
            tree = ast.parse(source_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and not parameters:
                    parameters = [arg.arg for arg in node.args.args if arg.arg not in ("self", "cursor", "conn", "db", "connection")]
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    found_tables = SQLiteParser.extract_tables(node.value)
                    if found_tables:
                        tables.extend(found_tables)
        except Exception:
            pass

        if not tables:
            tables = SQLiteParser.extract_tables(source_code)

        table = tables[0] if tables else None
        if not parameters:
            parameters = ["username"]

        invariants = [
            "SQL query structure must not be alterable by untrusted user input.",
            "Dynamic values must be bound using database driver parameter placeholders (?).",
            "Benign functionality for legitimate inputs must be strictly preserved.",
        ]

        if has_syntax_err:
            return {
                "input_kind": "PYTHON_CODE",
                "is_vulnerable": False,
                "vulnerability_type": "SYNTAX_ERROR",
                "severity": FindingSeverity.INFO,
                "confidence": "HIGH",
                "detected_table": table,
                "detected_parameters": parameters,
                "findings": ast_result.findings,
                "security_invariants": invariants,
                "potential_payloads": [],
                "summary": "Python syntax error prevents structural vulnerability analysis.",
            }

        if has_unsafe:
            findings = ast_result.findings
            return {
                "input_kind": "PYTHON_CODE",
                "is_vulnerable": True,
                "vulnerability_type": "SQL_INJECTION",
                "severity": FindingSeverity.HIGH,
                "confidence": "HIGH",
                "detected_table": table or "users",
                "detected_parameters": parameters,
                "findings": findings,
                "security_invariants": invariants,
                "potential_payloads": self.PROBE_PAYLOADS,
                "summary": (
                    "High-risk SQL injection detected: SQL query is dynamically constructed using "
                    "string concatenation or interpolation without parameter binding."
                ),
            }

        if has_parameterized:
            return {
                "input_kind": "PYTHON_CODE",
                "is_vulnerable": False,
                "vulnerability_type": "SQL_INJECTION",
                "severity": FindingSeverity.INFO,
                "confidence": "HIGH",
                "detected_table": table or "users",
                "detected_parameters": parameters,
                "findings": ast_result.findings,
                "security_invariants": invariants,
                "potential_payloads": [],
                "summary": "Query appears parameterized. Dynamic verification required to confirm execution safety.",
            }

        return {
            "input_kind": "PYTHON_CODE",
            "is_vulnerable": False,
            "vulnerability_type": "SQL_INJECTION",
            "severity": FindingSeverity.INFO,
            "confidence": "MEDIUM",
            "detected_table": table or "users",
            "detected_parameters": parameters,
            "findings": ast_result.findings,
            "security_invariants": invariants,
            "potential_payloads": [],
            "summary": "No obvious dynamic query concatenation detected in Python source.",
        }

    def _analyze_raw_sql(self, query: str) -> dict[str, Any]:
        """Analyze arbitrary raw SQLite SQL statement using SQLiteParser."""
        parsed = SQLiteParser.parse_query(query)
        table = parsed.tables[0] if parsed.tables else None
        parameters = parsed.parameters

        findings: list[AnalysisFinding] = []
        invariants = [
            "SQL query structure must be compiled independently of untrusted data.",
            f"User-supplied input for '{table or 'target'}' must use bound parameters (?).",
            "Benign functionality for legitimate inputs must be strictly preserved.",
        ]

        if not parsed.is_valid_syntax:
            return {
                "input_kind": "RAW_SQL",
                "is_vulnerable": False,
                "vulnerability_type": "SYNTAX_ERROR",
                "severity": FindingSeverity.INFO,
                "confidence": "HIGH",
                "detected_table": table,
                "detected_parameters": parameters,
                "findings": [
                    AnalysisFinding(
                        rule_id="SQLITE_SYNTAX_ERROR",
                        message=f"SQLite syntax error: {parsed.syntax_error}",
                        severity=FindingSeverity.INFO,
                        evidence=query,
                    )
                ],
                "security_invariants": invariants,
                "potential_payloads": [],
                "summary": f"Invalid SQLite statement: {parsed.syntax_error}",
            }

        if parsed.is_ddl_or_pragma:
            return {
                "input_kind": "RAW_SQL",
                "is_vulnerable": False,
                "vulnerability_type": None,
                "severity": FindingSeverity.INFO,
                "confidence": "HIGH",
                "detected_table": table,
                "detected_parameters": parameters,
                "findings": [
                    AnalysisFinding(
                        rule_id="SQLITE_DDL_OR_ADMIN",
                        message=f"Statement is a valid SQLite {parsed.statement_type.value} command.",
                        severity=FindingSeverity.INFO,
                        evidence=query,
                    )
                ],
                "security_invariants": invariants,
                "potential_payloads": [],
                "summary": f"Valid SQLite {parsed.statement_type.value} statement. {parsed.verification_limitation or ''}",
            }

        if parsed.is_parameterized:
            findings.append(
                AnalysisFinding(
                    rule_id="SQLI_PARAMETERIZED_QUERY",
                    message="Raw SQL query contains parameter markers ('?' or named parameters).",
                    severity=FindingSeverity.INFO,
                    evidence=query,
                )
            )
            return {
                "input_kind": "RAW_SQL",
                "is_vulnerable": False,
                "vulnerability_type": "SQL_INJECTION",
                "severity": FindingSeverity.INFO,
                "confidence": "HIGH",
                "detected_table": table or "users",
                "detected_parameters": parameters or ["username"],
                "findings": findings,
                "security_invariants": invariants,
                "potential_payloads": [],
                "summary": "Raw SQL statement already contains parameter placeholders.",
            }

        if parsed.has_dynamic_construction or "+" in query or "{" in query:
            findings.append(
                AnalysisFinding(
                    rule_id="SQLI_CONCATENATION_MARKER",
                    message="Query contains string concatenation or template markers inside the statement.",
                    severity=FindingSeverity.HIGH,
                    evidence=query,
                )
            )
            return {
                "input_kind": "RAW_SQL",
                "is_vulnerable": True,
                "vulnerability_type": "SQL_INJECTION",
                "severity": FindingSeverity.HIGH,
                "confidence": "HIGH",
                "detected_table": table or "users",
                "detected_parameters": ["username"],
                "findings": findings,
                "security_invariants": invariants,
                "potential_payloads": self.PROBE_PAYLOADS,
                "summary": "Query appears to concatenate dynamic substrings. Requires parameterization.",
            }

        if parsed.literal_predicates or (parsed.statement_type in (SQLiteStatementType.SELECT, SQLiteStatementType.UPDATE, SQLiteStatementType.DELETE) and "WHERE" in query.upper() and not parsed.is_parameterized):
            evidence_str = ", ".join(f"{p['column']} {p['operator']} {p['value']}" for p in parsed.literal_predicates) if parsed.literal_predicates else query[:100]
            findings.append(
                AnalysisFinding(
                    rule_id="SQLI_UNPARAMETERIZED_LITERAL",
                    message=(
                        f"Unparameterized value filter detected in query: '{evidence_str}'. "
                        "Directly embedding user input into this predicate permits SQL injection."
                    ),
                    severity=FindingSeverity.HIGH,
                    evidence=evidence_str,
                )
            )
            return {
                "input_kind": "RAW_SQL",
                "is_vulnerable": True,
                "vulnerability_type": "SQL_INJECTION",
                "severity": FindingSeverity.HIGH,
                "confidence": "HIGH",
                "detected_table": table or "users",
                "detected_parameters": parameters or ["username"],
                "findings": findings,
                "security_invariants": invariants,
                "potential_payloads": self.PROBE_PAYLOADS,
                "summary": (
                    f"Vulnerability identified: Query filter on '{', '.join(parameters) if parameters else 'filter'}' "
                    "uses raw literal embedding. Must be parameterized with '?'."
                ),
            }

        return {
            "input_kind": "RAW_SQL",
            "is_vulnerable": False,
            "vulnerability_type": "SQL_INJECTION",
            "severity": FindingSeverity.INFO,
            "confidence": "MEDIUM",
            "detected_table": table or "users",
            "detected_parameters": parameters,
            "findings": [
                AnalysisFinding(
                    rule_id="SQLI_STATIC_QUERY",
                    message="SQL query appears static without parameterizable user input fields.",
                    severity=FindingSeverity.INFO,
                    evidence=query,
                )
            ],
            "security_invariants": invariants,
            "potential_payloads": [],
            "summary": "Static SQL statement without identifiable user input concatenation.",
        }
