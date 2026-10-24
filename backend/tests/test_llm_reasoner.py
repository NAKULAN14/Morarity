"""
Tests for LLM Security Reasoning Module.
Enforces that the LLM is advisory, handles malformed inputs, produces structured hypotheses,
and never replaces the authoritative empirical verification engine.
"""

from app.llm.reasoner import LLMSecurityReasoner
from app.models.schemas import LLMReasoningResult


def test_llm_reasoner_handles_empty_input_safely():
    reasoner = LLMSecurityReasoner()
    res = reasoner.reason_about_source("")
    assert isinstance(res, LLMReasoningResult)
    assert res.status == "UNAVAILABLE"
    assert res.confidence == 0.0


def test_llm_reasoner_detects_dynamic_sql_concatenation_hypotheses():
    reasoner = LLMSecurityReasoner()
    vulnerable_code = """
def search_accounts(cursor, acct_id):
    cursor.execute("SELECT * FROM accounts WHERE id = '" + acct_id + "'")
    return cursor.fetchall()
"""
    res = reasoner.reason_about_source(vulnerable_code, input_type="python")
    assert isinstance(res, LLMReasoningResult)
    assert res.status == "ACTIVE"
    assert len(res.hypotheses) >= 1
    assert any("delimiter" in h.lower() or "boundary" in h.lower() for h in res.hypotheses)
    assert "Quote and delimiter handling" in res.recommended_test_categories
    assert len(res.additional_test_suggestions) >= 1
    assert res.confidence > 0.8


def test_llm_reasoner_identifies_safe_parameterized_query():
    reasoner = LLMSecurityReasoner()
    safe_code = """
def search_accounts(cursor, acct_id: str):
    cursor.execute("SELECT * FROM accounts WHERE id = ?", (acct_id,))
    return cursor.fetchall()
"""
    res = reasoner.reason_about_source(safe_code, input_type="python")
    assert isinstance(res, LLMReasoningResult)
    assert any("parameter" in h.lower() for h in res.hypotheses)
    assert res.confidence >= 0.9


def test_llm_reasoner_flags_incomplete_patch_sanitization():
    reasoner = LLMSecurityReasoner()
    orig = "def q(cursor, x): cursor.execute('SELECT * FROM t WHERE x = ' + x)"
    incomplete_patch = """
def q(cursor, x):
    cleaned = x.replace('--', '')
    cursor.execute("SELECT * FROM t WHERE x = '" + cleaned + "'")
"""
    res = reasoner.reason_about_patch(orig, incomplete_patch)
    assert isinstance(res, LLMReasoningResult)
    assert len(res.patch_concerns) >= 1
    assert any("incomplete" in c.lower() or "sanitize" in c.lower() or "quote" in c.lower() for c in res.patch_concerns)


def test_llm_reasoner_flags_regression_patch():
    reasoner = LLMSecurityReasoner()
    orig = "def q(cursor, x): cursor.execute('SELECT * FROM t WHERE x = ' + x)"
    regression_patch = """
def q(cursor, x):
    cursor.execute("SELECT * FROM t WHERE id = 1")
    return cursor.fetchall()
"""
    res = reasoner.reason_about_patch(orig, regression_patch)
    assert isinstance(res, LLMReasoningResult)
    assert len(res.patch_concerns) >= 1
    assert any("regression" in c.lower() or "hardcoded" in c.lower() for c in res.patch_concerns)


def test_llm_suggested_tests_contain_executable_payloads():
    reasoner = LLMSecurityReasoner()
    code = "SELECT id FROM logs WHERE level = '" + "debug" + "'"
    suggestions = reasoner.suggest_adaptive_tests(code)
    assert isinstance(suggestions, list)
    assert len(suggestions) >= 1
    assert "payload" in suggestions[0]
    assert suggestions[0]["category"] in ["Quote and delimiter handling", "Comment-based SQL injection"]
