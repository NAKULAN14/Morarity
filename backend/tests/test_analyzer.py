
from app.analyzer.ast_analyzer import analyze_sql_injection


def test_detects_string_concatenation():
    source = """
def get_user(cursor, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"""

    result = analyze_sql_injection(source)

    assert result.supported is True
    assert any(
        finding.rule_id == "SQLI_UNSAFE_QUERY"
        for finding in result.findings
    )


def test_detects_f_string():
    source = """
def get_user(cursor, user_id):
    cursor.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    )
"""

    result = analyze_sql_injection(source)

    assert any(
        finding.rule_id == "SQLI_UNSAFE_QUERY"
        for finding in result.findings
    )


def test_recognizes_parameterized_query():
    source = """
def get_user(cursor, user_id):
    cursor.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    )
"""

    result = analyze_sql_injection(source)

    assert any(
        finding.rule_id == "SQLI_PARAMETERIZED_QUERY"
        for finding in result.findings
    )


def test_handles_invalid_python():
    source = """
def broken(
"""

    result = analyze_sql_injection(source)

    assert result.supported is False
    assert any(
        finding.rule_id == "PYTHON_SYNTAX_ERROR"
        for finding in result.findings
    )


def test_handles_empty_source():
    result = analyze_sql_injection("")

    assert result.supported is False
    assert result.summary == "No source code was provided."
