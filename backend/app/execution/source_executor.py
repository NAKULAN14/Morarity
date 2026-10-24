"""
Controlled Source Execution and Provenance Verification.

Safely parses and executes supported Python/SQLite source code in a restricted
local environment against a seeded in-memory database, and verifies the provenance
correspondence between submitted source code and runtime target objects.
"""

import ast
import inspect
import re
import sqlite3
from typing import Any, Callable, Optional

from app.analysis.sqlite_parser import SQLiteParser


DISALLOWED_NAMES = {
    "eval",
    "exec",
    "compile",
    "open",
    "__import__",
    "globals",
    "locals",
    "getattr",
    "setattr",
    "delattr",
    "system",
    "popen",
    "spawn",
    "subprocess",
    "socket",
    "requests",
    "urllib",
    "shutil",
    "os",
    "sys",
}

SAFE_BUILTINS = {
    "range": range,
    "len": len,
    "str": str,
    "int": int,
    "float": float,
    "tuple": tuple,
    "list": list,
    "dict": dict,
    "bool": bool,
    "isinstance": isinstance,
    "Exception": Exception,
    "None": None,
    "True": True,
    "False": False,
}


def check_source_equivalence(code1: Optional[str], code2: Optional[str]) -> bool:
    """
    Safely and conservatively compare two Python source strings for structural equivalence.
    Uses AST dump comparison which preserves exact string literals, constants, identifiers,
    and expressions, while safely ignoring non-semantic comments and exterior formatting.
    Does NOT collapse whitespace or remove '#' characters inside string literals.
    If equivalence cannot be established reliably, returns False.
    """
    if not code1 or not code2:
        return False
    if code1 == code2:
        return True
    try:
        tree1 = ast.parse(code1)
        tree2 = ast.parse(code2)
        return ast.dump(tree1) == ast.dump(tree2)
    except Exception:
        return False


def normalize_code(code: str) -> str:
    """
    Safe AST-based code normalization preserving string and constant values.
    Does NOT collapse whitespace or remove '#' characters inside string literals.
    """
    if not code:
        return ""
    try:
        tree = ast.parse(code)
        return ast.dump(tree)
    except Exception:
        return code.strip()


class SourceSecurityValidator(ast.NodeVisitor):
    """
    Validates that submitted Python source uses only the safe, supported
    subset for database query execution.
    """

    def __init__(self) -> None:
        self.disallowed_found: list[str] = []
        self.functions_found: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        self.disallowed_found.append("import statements are disallowed in submitted source")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.disallowed_found.append("from-import statements are disallowed in submitted source")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions_found.append(node.name)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in DISALLOWED_NAMES:
            self.disallowed_found.append(f"disallowed identifier: '{node.id}'")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr.startswith("__") and node.attr.endswith("__"):
            self.disallowed_found.append(f"dunder attribute access disallowed: '{node.attr}'")
        self.generic_visit(node)


class SourceBoundUserApp:
    """
    Local runtime target directly compiled from and bound to submitted Python source.
    Executes in a restricted namespace against an isolated in-memory SQLite database.
    """

    def __init__(self, source_code: str, query_func: Callable) -> None:
        self.source_code = source_code
        self.query_func = query_func
        self.target_type = "SUBMITTED_SOURCE_EXECUTION"
        self.target_provenance = "RESTRICTED_SOURCE_ENV"
        self.submitted_source_executed = True
        self.source_runtime_match = True
        self.connection = sqlite3.connect(":memory:")
        self._init_db()

    def _init_db(self) -> None:
        tables = SQLiteParser.extract_tables(self.source_code)
        columns = SQLiteParser.extract_columns(self.source_code)
        SQLiteParser.synthesize_mock_db(self.connection, tables, columns)

    def search_users(self, username: str) -> list[dict[str, Any]]:
        # Inspect query function parameter signature
        sig = inspect.signature(self.query_func)
        param_names = list(sig.parameters.keys())
        first_param = param_names[0] if param_names else "cursor"

        target = self.connection if first_param in ("conn", "connection", "db") else self.connection.cursor()
        cursor = self.connection.cursor() if target is self.connection else target

        try:
            raw_result = self.query_func(target, username)
        except sqlite3.OperationalError as op_err:
            err_msg = str(op_err)
            if "no such column:" in err_msg:
                missing_col = err_msg.split("no such column:")[-1].strip().split()[0].split(".")[-1]
                tables = SQLiteParser.extract_tables(self.source_code)
                for tbl in tables:
                    try:
                        self.connection.execute(f"ALTER TABLE {tbl} ADD COLUMN {missing_col} TEXT")
                    except Exception:
                        pass
                raw_result = self.query_func(target, username)
            else:
                raise

        if raw_result is None:
            try:
                raw_result = cursor.fetchall()
            except Exception:
                try:
                    if hasattr(target, "fetchall"):
                        raw_result = target.fetchall()
                    else:
                        raw_result = []
                except Exception:
                    raw_result = []

        # Normalize rows into list of dicts
        if raw_result is None:
            return []

        rows: list[Any] = raw_result if isinstance(raw_result, (list, tuple)) else [raw_result]
        normalized: list[dict[str, Any]] = []
        col_names = [d[0] for d in cursor.description] if getattr(cursor, "description", None) else []

        for r in rows:
            if isinstance(r, dict):
                normalized.append(r)
            elif isinstance(r, (list, tuple)):
                if col_names:
                    row_dict = {col_names[i]: r[i] for i in range(min(len(col_names), len(r)))}
                    if "id" not in row_dict and len(r) > 0:
                        row_dict["id"] = r[0]
                    if "username" not in row_dict and len(r) > 1:
                        row_dict["username"] = str(r[1])
                    normalized.append(row_dict)
                else:
                    normalized.append({
                        "id": r[0] if len(r) > 0 else None,
                        "username": r[1] if len(r) > 1 else "",
                        "role": r[2] if len(r) > 2 else "",
                        "email": r[3] if len(r) > 3 else "",
                    })
        return normalized

    def close(self) -> None:
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass


class ControlledSourceExecutor:
    """
    Safely compiles submitted Python source into a runnable target
    within a restricted namespace.
    """

    @classmethod
    def validate_source(cls, source_code: str) -> tuple[bool, str, Optional[str]]:
        """Validate that submitted source is safe and adheres to supported structure."""
        if not source_code or not source_code.strip():
            return False, "Source code is empty.", None

        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            return False, f"Syntax error in submitted source: {exc.msg}", None

        validator = SourceSecurityValidator()
        validator.visit(tree)

        if validator.disallowed_found:
            return (
                False,
                f"Source violates security restrictions: {', '.join(validator.disallowed_found)}",
                None,
            )

        if not validator.functions_found:
            return False, "No function definition found in submitted source.", None

        # Pick the query function (preferably get_user_by_username or first defined)
        func_name = validator.functions_found[0]
        for name in validator.functions_found:
            if "get_user" in name or "search" in name:
                func_name = name
                break

        return True, "Source validated successfully.", func_name

    @classmethod
    def create_app_from_source(cls, source_code: str) -> tuple[Optional[SourceBoundUserApp], str]:
        """
        Compile validated source code into a SourceBoundUserApp instance.
        """
        valid, message, func_name = cls.validate_source(source_code)
        if not valid or func_name is None:
            return None, message

        try:
            restricted_globals = {"__builtins__": SAFE_BUILTINS}
            restricted_locals: dict[str, Any] = {}
            code_obj = compile(source_code, "<submitted_source>", "exec")
            exec(code_obj, restricted_globals, restricted_locals)

            query_func = restricted_locals.get(func_name)
            if not callable(query_func):
                return None, f"Extracted symbol '{func_name}' is not callable."

            app = SourceBoundUserApp(source_code=source_code, query_func=query_func)
            return app, "Successfully initialized submitted source runtime environment."
        except Exception as exc:
            return None, f"Failed to instantiate submitted source: {exc}"


def verify_target_provenance(
    submitted_source: Optional[str],
    target_app: Any,
) -> tuple[bool, str, str, bool]:
    """
    Determine whether a runtime target corresponds to the submitted source.

    Returns:
        (source_runtime_match, target_type, target_provenance, submitted_source_executed)
    """
    if target_app is None:
        return False, "CONTROLLED_FIXTURE", "NO_TARGET_PROVIDED", False

    # 1. Direct SourceBoundUserApp
    if isinstance(target_app, SourceBoundUserApp):
        if submitted_source is None:
            return False, target_app.target_type, target_app.target_provenance, True
        match = check_source_equivalence(target_app.source_code, submitted_source)
        return match, target_app.target_type, target_app.target_provenance, match

    # 2. Registered scenario application with attached source
    app_source = getattr(target_app, "SOURCE_CODE", getattr(target_app, "source_code", None))
    if app_source is not None and submitted_source is not None:
        match = check_source_equivalence(app_source, submitted_source)
        target_type = "REAL_LOCAL_APPLICATION"
        provenance = "REGISTERED_SCENARIO_MATCH" if match else "PROVENANCE_MISMATCH"
        return match, target_type, provenance, match

    # 3. Unverified external instance
    if submitted_source is None:
        return False, "REAL_LOCAL_APPLICATION", "UNVERIFIED_EXTERNAL_INSTANCE", False

    return False, "REAL_LOCAL_APPLICATION", "PROVENANCE_NOT_ESTABLISHED", False
