
from app.verification.patch_comparator import PatchComparator


VULNERABLE_SOURCE = """
def get_user(cursor, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
"""


PATCHED_SOURCE = """
def get_user(cursor, username):
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    )
"""


STILL_VULNERABLE_SOURCE = """
def get_user(cursor, username):
    cursor.execute(
        f"SELECT * FROM users WHERE username = '{username}'"
    )
"""


UNKNOWN_QUERY_SOURCE = """
def get_user(cursor, username):
    query = build_query(username)
    cursor.execute(query)
"""


def test_detects_static_improvement_after_parameterization():
    comparator = PatchComparator()

    result = comparator.compare(
        VULNERABLE_SOURCE,
        PATCHED_SOURCE,
    )

    assert result.status == "PATCH_PATTERN_IMPROVED"
    assert result.static_improvement_detected is True
    assert "SQLI_UNSAFE_QUERY" in result.original_rule_ids
    assert "SQLI_PARAMETERIZED_QUERY" in result.patched_rule_ids
    assert result.dynamic_verification_performed is False


def test_reports_unsafe_pattern_still_present():
    comparator = PatchComparator()

    result = comparator.compare(
        VULNERABLE_SOURCE,
        STILL_VULNERABLE_SOURCE,
    )

    assert result.status == "VULNERABILITY_REMAINS"
    assert result.static_improvement_detected is False
    assert "SQLI_UNSAFE_QUERY" in result.patched_rule_ids


def test_unknown_patched_query_is_inconclusive():
    comparator = PatchComparator()

    result = comparator.compare(
        VULNERABLE_SOURCE,
        UNKNOWN_QUERY_SOURCE,
    )

    assert result.status == "INCONCLUSIVE"
    assert "SQLI_UNKNOWN_QUERY" in result.patched_rule_ids


def test_baseline_without_detected_unsafe_query():
    comparator = PatchComparator()

    result = comparator.compare(
        PATCHED_SOURCE,
        PATCHED_SOURCE,
    )

    assert result.status == "BASELINE_NOT_DETECTED"
    assert result.static_improvement_detected is False


def test_invalid_python_is_unsupported():
    comparator = PatchComparator()

    result = comparator.compare(
        VULNERABLE_SOURCE,
        "def broken(:",
    )

    assert result.status == "ANALYSIS_UNSUPPORTED"
    assert result.static_improvement_detected is False
