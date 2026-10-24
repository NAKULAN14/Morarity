import ast
from typing import Optional
from app.models.schemas import (
    AnalysisFinding,
    AnalysisResult,
    FindingSeverity,
)
class SQLInjectionAnalyzer:
    """
    AST-based analyzer for identifying potentially unsafe SQL query
    construction in Python applications using SQLite.

    This analyzer performs structural analysis only. It does not
    determine exploitability by itself.
    """

    SQL_EXECUTION_METHODS = {
        "execute",
        "executemany",
    }

    SQL_KEYWORDS = (
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "REPLACE",
        "CREATE",
        "DROP",
        "ALTER",
        "PRAGMA",
        "WITH",
        "BEGIN",
        "EXPLAIN",
    )

    def analyze(self, source_code: str) -> AnalysisResult:
        """
        Analyze Python source code and return structural findings.
        """

        if not source_code or not source_code.strip():
            return AnalysisResult(
                supported=False,
                vulnerability_type=None,
                findings=[],
                security_invariants=[],
                summary="No source code was provided.",
            )

        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            return AnalysisResult(
                supported=False,
                vulnerability_type=None,
                findings=[
                    AnalysisFinding(
                        rule_id="PYTHON_SYNTAX_ERROR",
                        message=f"Python syntax error: {exc.msg}",
                        severity=FindingSeverity.INFO,
                        line=exc.lineno,
                    )
                ],
                security_invariants=[],
                summary="Source code could not be analyzed because it contains a syntax error.",
            )

        findings: list[AnalysisFinding] = []
        visitor = _SQLQueryVisitor()

        visitor.visit(tree)

        for query in visitor.queries:
            finding = self._analyze_query(query)

            if finding is not None:
                findings.append(finding)

        if not visitor.queries:
            return AnalysisResult(
                supported=True,
                vulnerability_type=None,
                findings=[
                    AnalysisFinding(
                        rule_id="NO_SQL_EXECUTION_FOUND",
                        message=(
                            "No recognized SQL execution calls were found. "
                            "This does not prove that the source code is safe."
                        ),
                        severity=FindingSeverity.INFO,
                    )
                ],
                security_invariants=[
                    "SQL query values must be passed separately from SQL query structure."
                ],
                summary=(
                    "No recognized SQL execution calls were found. "
                    "The code may be outside the analyzer's supported scope."
                ),
            )

        has_unsafe_query = any(
            finding.rule_id == "SQLI_UNSAFE_QUERY"
            for finding in findings
        )

        has_unknown_query = any(
            finding.rule_id == "SQLI_UNKNOWN_QUERY"
            for finding in findings
        )

        if has_unsafe_query:
            summary = (
                "Potentially unsafe SQL query construction was detected. "
                "Dynamic verification is required to determine exploitability."
            )
        elif has_unknown_query:
            summary = (
                "Some SQL query structures could not be confidently classified. "
                "Additional analysis or execution evidence is required."
            )
        else:
            summary = (
                "Recognized SQL execution calls appear to use static query "
                "structures or parameterized execution. Dynamic verification "
                "is still required."
            )

        return AnalysisResult(
            supported=True,
            vulnerability_type="SQL_INJECTION",
            findings=findings,
            security_invariants=[
                "SQL query structure must not be controlled by untrusted input.",
                "User-controlled values should be passed through query parameters.",
                "Required application functionality must remain intact.",
            ],
            summary=summary,
        )

    def _analyze_query(
        self,
        query: "_SQLQuery",
    ) -> Optional[AnalysisFinding]:
        """
        Classify a recognized SQL execution call.
        """

        if query.query_node is None:
            return AnalysisFinding(
                rule_id="SQLI_UNKNOWN_QUERY",
                message=(
                    "The SQL query argument could not be identified. "
                    "The execution call requires further analysis."
                ),
                severity=FindingSeverity.MEDIUM,
                line=query.line,
            )

        query_node = query.query_node

        if self._is_parameterized(query):
            return AnalysisFinding(
                rule_id="SQLI_PARAMETERIZED_QUERY",
                message=(
                    "The SQL query appears to use parameterized execution. "
                    "Verify that the query structure is static and that "
                    "all untrusted values are passed as parameters."
                ),
                severity=FindingSeverity.INFO,
                line=query.line,
                evidence=ast.unparse(query_node),
            )

        if self._is_dynamic_query(query_node):
            return AnalysisFinding(
                rule_id="SQLI_UNSAFE_QUERY",
                message=(
                    "The SQL query is constructed dynamically using "
                    "string concatenation, interpolation, or formatting. "
                    "This may allow untrusted input to alter SQL structure."
                ),
                severity=FindingSeverity.HIGH,
                line=query.line,
                evidence=ast.unparse(query_node),
            )

        if self._is_sql_literal(query_node):
            return AnalysisFinding(
                rule_id="SQLI_STATIC_QUERY",
                message=(
                    "The SQL query appears to be a static string literal. "
                    "Check whether the query contains any externally "
                    "controlled values."
                ),
                severity=FindingSeverity.INFO,
                line=query.line,
                evidence=ast.unparse(query_node),
            )

        return AnalysisFinding(
            rule_id="SQLI_UNKNOWN_QUERY",
            message=(
                "The SQL query structure could not be confidently classified. "
                "Further analysis is required."
            ),
            severity=FindingSeverity.MEDIUM,
            line=query.line,
            evidence=ast.unparse(query_node),
        )

    def _is_parameterized(self, query: "_SQLQuery") -> bool:
        """
        Identify execution calls that provide query parameters separately.

        Examples:
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
        """

        return len(query.call_args) >= 2

    def _is_dynamic_query(self, node: ast.AST) -> bool:
        """
        Identify common forms of dynamically constructed SQL, including
        f-strings, string concatenation (+), %-formatting, and .format().
        """
        if isinstance(node, ast.JoinedStr):
            return True

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._contains_string_literal(node)

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return self._contains_string_literal(node)

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in {"format", "replace"}:
                    return True

            if isinstance(node.func, ast.Name):
                if node.func.id in {"format", "join"}:
                    return True

        return False

    def _contains_string_literal(self, node: ast.AST) -> bool:
        """
        Check whether a concatenation expression contains a string literal.

        This helps distinguish common SQL string concatenation from
        unrelated arithmetic expressions.
        """

        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if self._is_sql_string(child.value):
                    return True

        return False

    def _is_sql_literal(self, node: ast.AST) -> bool:
        """
        Determine whether a query expression is a SQL string literal.
        """

        if not isinstance(node, ast.Constant):
            return False

        if not isinstance(node.value, str):
            return False

        return self._is_sql_string(node.value)

    def _is_sql_string(self, value: str) -> bool:
        """
        Check whether a string begins with a recognized SQL keyword.
        """

        normalized = value.lstrip().upper()

        return any(
            normalized.startswith(keyword)
            for keyword in self.SQL_KEYWORDS
        )


class _SQLQuery:
    """
    Internal representation of a recognized SQL execution call.
    """

    def __init__(
        self,
        query_node: Optional[ast.AST],
        call_args: list[ast.AST],
        line: int,
    ):
        self.query_node = query_node
        self.call_args = call_args
        self.line = line


class _SQLQueryVisitor(ast.NodeVisitor):
    """
    Locate execute() and executemany() calls and resolve simple
    SQL variables assigned earlier in the same scope.
    """

    def __init__(self):
        self.queries: list[_SQLQuery] = []
        self.assignments: dict[str, ast.AST] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.AST):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.assignments[target.id] = node.value

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.assignments[node.target.id] = node.value

        self.generic_visit(node)

    def _resolve_node(self, node: Optional[ast.AST], depth: int = 0) -> Optional[ast.AST]:
        """Recursively resolve variable assignments in local data-flow."""
        if depth > 8 or node is None:
            return node
        if isinstance(node, ast.Name) and node.id in self.assignments:
            return self._resolve_node(self.assignments[node.id], depth + 1)
        return node

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in SQLInjectionAnalyzer.SQL_EXECUTION_METHODS
        ):
            query_node = node.args[0] if node.args else None
            query_node = self._resolve_node(query_node)

            self.queries.append(
                _SQLQuery(
                    query_node=query_node,
                    call_args=node.args,
                    line=node.lineno,
                )
            )

        self.generic_visit(node)


def analyze_sql_injection(source_code: str) -> AnalysisResult:
    """
    Convenience function for API routes and other modules.
    """

    analyzer = SQLInjectionAnalyzer()
    return analyzer.analyze(source_code)
