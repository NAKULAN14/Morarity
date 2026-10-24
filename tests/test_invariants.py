from app.analyzer.ast_analyzer import analyze_sql_injection
from app.analyzer.invariants import generate_invariants


def test_generates_default_invariants():
    source = """
def get_user(cursor, user_id):
    cursor.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    )
"""
    analysis = analyze_sql_injection(source)
    invariants = generate_invariants(analysis)

    assert any("query structure" in item.lower() for item in invariants)
    assert any("functionality" in item.lower() for item in invariants)


def test_adds_unsafe_query_invariant():
    source = """
def get_user(cursor, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"""
    analysis = analyze_sql_injection(source)
    invariants = generate_invariants(analysis)

    assert "SQLI_UNSAFE_QUERY" in [finding.rule_id for finding in analysis.findings]
    assert invariants[-1].lower() == (
    "dynamically constructed sql must be replaced with "
    "a safe query structure."
)


def test_adds_unknown_query_invariant():
    source = """
def get_user(cursor, query):
    cursor.execute(query)
"""
    analysis = analyze_sql_injection(source)
    invariants = generate_invariants(analysis)

    assert "SQLI_UNKNOWN_QUERY" in [finding.rule_id for finding in analysis.findings]
    assert invariants[-1].lower() == (
    "unclassified sql execution paths must be investigated "
    "before declaring the patch verified."
)


def test_invariants_are_unique():
    source = """
def get_user(cursor, user_id):
    cursor.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    )
"""
    analysis = analyze_sql_injection(source)
    invariants = generate_invariants(analysis)

    assert len(invariants) == len(set(invariants))