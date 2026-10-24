"""
Tests for Generalized SQLite SQL & Python Analysis in Moriarty 2.0.
Verifies support for arbitrary SQLite queries (SELECT, INSERT, UPDATE, DELETE, CTE, JOIN, PRAGMA)
and Python database code with diverse function/variable/table names.
"""

import pytest
from app.analysis.sqlite_parser import SQLiteParser, SQLiteStatementType
from app.patching.sql_analyzer import SQLVulnerabilityAnalyzer
from app.patching.generator import SQLPatchGenerator
from app.execution.source_executor import ControlledSourceExecutor


def test_sqlite_parser_classifies_statement_types():
    assert SQLiteParser.classify_statement_type("SELECT * FROM users") == SQLiteStatementType.SELECT
    assert SQLiteParser.classify_statement_type("INSERT INTO logs (lvl) VALUES ('ERR')") == SQLiteStatementType.INSERT
    assert SQLiteParser.classify_statement_type("UPDATE items SET price = 10") == SQLiteStatementType.UPDATE
    assert SQLiteParser.classify_statement_type("DELETE FROM sessions WHERE id = 1") == SQLiteStatementType.DELETE
    assert SQLiteParser.classify_statement_type("WITH cte AS (SELECT 1) SELECT * FROM cte") == SQLiteStatementType.WITH_CTE
    assert SQLiteParser.classify_statement_type("PRAGMA table_info(users)") == SQLiteStatementType.PRAGMA
    assert SQLiteParser.classify_statement_type("CREATE TABLE test (id INT)") == SQLiteStatementType.CREATE_TABLE


def test_sqlite_parser_extracts_tables_and_columns():
    q = "SELECT u.id, u.username, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.username = 'alice'"
    parsed = SQLiteParser.parse_query(q)
    assert parsed.is_valid_syntax is True
    assert "users" in parsed.tables or "orders" in parsed.tables
    assert parsed.can_dynamically_verify is True


def test_sqlite_parser_detects_parameterized_markers():
    q_param = "SELECT * FROM accounts WHERE acc_num = ? AND pin = :pin"
    parsed = SQLiteParser.parse_query(q_param)
    assert parsed.is_parameterized is True
    assert "?" in parsed.parameter_markers
    assert ":pin" in parsed.parameter_markers


def test_sqlite_parser_handles_ddl_and_pragma_limitations():
    q_ddl = "CREATE INDEX idx_user ON users(username)"
    parsed = SQLiteParser.parse_query(q_ddl)
    assert parsed.is_ddl_or_pragma is True
    assert parsed.can_dynamically_verify is False
    assert "DDL/administrative operation" in parsed.verification_limitation


def test_analyzer_evaluates_arbitrary_raw_sql_statements():
    analyzer = SQLVulnerabilityAnalyzer()

    # 1. Unsafe raw INSERT with literal string
    res_insert = analyzer.analyze("INSERT INTO audit_logs (level, msg) VALUES ('WARN', 'Unauthorized access')")
    assert res_insert["input_kind"] == "RAW_SQL"
    assert "audit_logs" in (res_insert["detected_table"] or "")

    # 2. Unsafe raw UPDATE
    res_update = analyzer.analyze("UPDATE products SET price = 29.99 WHERE sku = 'SKU-999'")
    assert res_update["input_kind"] == "RAW_SQL"
    assert res_update["is_vulnerable"] is True
    assert "products" in (res_update["detected_table"] or "")

    # 3. Safe parameterized query on arbitrary table
    res_safe = analyzer.analyze("SELECT id, total FROM orders WHERE customer_id = ? AND status = ?")
    assert res_safe["is_vulnerable"] is False
    assert any(f.rule_id == "SQLI_PARAMETERIZED_QUERY" for f in res_safe["findings"])

    # 4. Valid DDL / administrative
    res_pragma = analyzer.analyze("PRAGMA foreign_keys = ON")
    assert res_pragma["is_vulnerable"] is False
    assert res_pragma["vulnerability_type"] is None


def test_analyzer_evaluates_python_with_custom_names_and_tables():
    analyzer = SQLVulnerabilityAnalyzer()

    # Function with custom function name and non-users table
    code_unsafe = (
        "def query_inventory(cursor, item_sku: str):\n"
        "    sql = f\"SELECT id, name, stock FROM inventory WHERE sku = '{item_sku}'\"\n"
        "    cursor.execute(sql)\n"
        "    return cursor.fetchall()\n"
    )
    res = analyzer.analyze(code_unsafe)
    assert res["input_kind"] == "PYTHON_CODE"
    assert res["is_vulnerable"] is True
    assert "inventory" in (res["detected_table"] or "")
    assert "item_sku" in res["detected_parameters"]


def test_controlled_source_executor_instantiates_custom_schema():
    # Python code querying custom 'orders' table
    code = (
        "def find_order(cursor, order_id: str):\n"
        "    cursor.execute(\"SELECT id, total, status FROM orders WHERE id = ?\", (order_id,))\n"
        "    return cursor.fetchall()\n"
    )
    app, msg = ControlledSourceExecutor.create_app_from_source(code)
    assert app is not None
    assert "Successfully initialized" in msg

    # Execute against synthesized in-memory SQLite database
    rows = app.search_users("1")
    assert isinstance(rows, list)
    app.close()


def test_patch_generator_preserves_custom_function_and_table():
    generator = SQLPatchGenerator()
    code = (
        "def fetch_employee(cursor, emp_id: str):\n"
        "    query = \"SELECT id, department, salary FROM employees WHERE emp_id = '\" + emp_id + \"'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    res = generator.generate_patch(code)
    assert "fetch_employee" in res["patched_code"]
    assert "employees" in res["patched_code"]
    assert "emp_id" in res["patched_code"]
    assert "?" in res["patched_code"]
    assert res["is_verified"] is False
