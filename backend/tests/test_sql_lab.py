"""
Tests for Moriarty SQL Security Lab: Vulnerability Analysis, Deterministic Patch Generation,
and Continuous Empirical Verification.
"""

from app.models.schemas import (
    ContinuousEvaluationRequest,
    FindingSeverity,
    LabVerificationRequest,
    PatchGenerationRequest,
    SQLAnalysisRequest,
    Verdict,
)
from app.patching.generator import SQLPatchGenerator
from app.patching.sql_analyzer import SQLVulnerabilityAnalyzer
from app.api.routes import (
    analyze_sql_input,
    continuous_evaluate,
    generate_sql_patch,
    verify_lab_patch,
)


def test_analyzer_detects_vulnerable_raw_sql():
    analyzer = SQLVulnerabilityAnalyzer()
    raw_query = "SELECT id, username, role, email FROM users WHERE username = 'admin'"
    result = analyzer.analyze(raw_query)

    assert result["input_kind"] == "RAW_SQL"
    assert result["is_vulnerable"] is True
    assert result["severity"] == FindingSeverity.HIGH
    assert result["detected_table"] == "users"
    assert "username" in result["detected_parameters"]
    assert len(result["potential_payloads"]) > 0
    assert any(f.rule_id == "SQLI_UNPARAMETERIZED_LITERAL" for f in result["findings"])


def test_analyzer_detects_safe_parameterized_raw_sql():
    analyzer = SQLVulnerabilityAnalyzer()
    safe_query = "SELECT id, username, role, email FROM users WHERE username = ?"
    result = analyzer.analyze(safe_query)

    assert result["input_kind"] == "RAW_SQL"
    assert result["is_vulnerable"] is False
    assert result["severity"] == FindingSeverity.INFO
    assert any(f.rule_id == "SQLI_PARAMETERIZED_QUERY" for f in result["findings"])


def test_analyzer_detects_vulnerable_python_concatenation():
    analyzer = SQLVulnerabilityAnalyzer()
    py_code = (
        "def get_user_by_username(cursor, username: str):\n"
        "    query = \"SELECT id, username, role, email FROM users WHERE username = '\" + username + \"'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    result = analyzer.analyze(py_code)

    assert result["input_kind"] == "PYTHON_CODE"
    assert result["is_vulnerable"] is True
    assert result["severity"] == FindingSeverity.HIGH
    assert result["detected_table"] == "users"
    assert "username" in result["detected_parameters"]


def test_analyzer_detects_vulnerable_python_fstring():
    analyzer = SQLVulnerabilityAnalyzer()
    py_code = (
        "def get_user_by_username(cursor, username: str):\n"
        "    query = f\"SELECT id, username, role, email FROM users WHERE username = '{username}'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    result = analyzer.analyze(py_code)

    assert result["input_kind"] == "PYTHON_CODE"
    assert result["is_vulnerable"] is True
    assert result["severity"] == FindingSeverity.HIGH


def test_generator_creates_parameterized_patch_from_raw_sql():
    generator = SQLPatchGenerator()
    raw_query = "SELECT id, username, role, email FROM users WHERE username = 'admin'"
    patch_result = generator.generate_patch(raw_query)

    assert patch_result["input_kind"] == "RAW_SQL"
    assert "?" in patch_result["patched_sql"]
    assert "admin" not in patch_result["patched_sql"]
    assert "def get_user_by_username" in patch_result["executable_patched_source"]
    assert patch_result["generation_method"] == "DETERMINISTIC_AST_PARAMETERIZER"
    assert patch_result["is_verified"] is False
    assert len(patch_result["invariants_enforced"]) > 0
    assert len(patch_result["diff_lines"]) > 0


def test_generator_creates_parameterized_patch_from_python():
    generator = SQLPatchGenerator()
    py_code = (
        "def get_user_by_username(cursor, username: str):\n"
        "    query = \"SELECT id, username, role, email FROM users WHERE username = '\" + username + \"'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    patch_result = generator.generate_patch(py_code)

    assert patch_result["input_kind"] == "PYTHON_CODE"
    assert "cursor.execute(" in patch_result["patched_code"]
    assert "?" in patch_result["patched_code"]
    assert "(username,)" in patch_result["patched_code"]
    assert patch_result["is_verified"] is False


def test_lab_verify_valid_generated_patch_is_verified():
    """Empirical verification: valid parameterized patch produces VERIFIED."""
    orig_code = (
        "def get_user_by_username(cursor, username: str):\n"
        "    query = \"SELECT id, username, role, email FROM users WHERE username = '\" + username + \"'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    patched_code = (
        "def get_user_by_username(cursor, username: str):\n"
        "    cursor.execute(\n"
        "        \"SELECT id, username, role, email FROM users WHERE username = ?\",\n"
        "        (username,),\n"
        "    )\n"
        "    return cursor.fetchall()\n"
    )

    req = LabVerificationRequest(
        original_source=orig_code,
        candidate_patch=patched_code,
        source_revision=1,
        patch_revision=1,
        max_tests=3,
    )
    response = verify_lab_patch(req)

    assert response.verdict == Verdict.VERIFIED
    assert response.submitted_source_executed is True
    assert response.source_runtime_match is True
    assert len(response.tests_executed) > 0
    assert response.final_action == "STOP_VERIFIED"


def test_lab_verify_incomplete_sanitization_is_rejected():
    """Empirical verification: naive patch that strips '--' is challenged and REJECTED."""
    orig_code = (
        "def get_user_by_username(cursor, username: str):\n"
        "    query = \"SELECT id, username, role, email FROM users WHERE username = '\" + username + \"'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    incomplete_patch = (
        "def get_user_by_username(cursor, username: str):\n"
        "    sanitized = username.replace('--', '')\n"
        "    query = \"SELECT id, username, role, email FROM users WHERE username = '\" + sanitized + \"'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )

    req = LabVerificationRequest(
        original_source=orig_code,
        candidate_patch=incomplete_patch,
        source_revision=1,
        patch_revision=1,
        max_tests=3,
    )
    response = verify_lab_patch(req)

    assert response.verdict == Verdict.REJECTED
    assert response.submitted_source_executed is True
    assert response.final_action == "STOP_REJECTED"


def test_lab_verify_regression_patch_is_inconclusive():
    """Empirical verification: patch that breaks benign lookup produces INCONCLUSIVE."""
    orig_code = (
        "def get_user_by_username(cursor, username: str):\n"
        "    query = \"SELECT id, username, role, email FROM users WHERE username = '\" + username + \"'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    # Patch blocks injection (returns empty, so 0 unauthorized rows) but breaks benign lookup
    regression_patch = (
        "def get_user_by_username(cursor, username: str):\n"
        "    return []\n"
    )

    req = LabVerificationRequest(
        original_source=orig_code,
        candidate_patch=regression_patch,
        source_revision=1,
        patch_revision=1,
        max_tests=3,
    )
    response = verify_lab_patch(req)

    assert response.verdict == Verdict.INCONCLUSIVE
    assert response.submitted_source_executed is True


def test_generator_sets_is_verified_false():
    """Verify that patch generator strictly emits candidate patches with is_verified=False."""
    generator = SQLPatchGenerator()
    res_sql = generator.generate_patch("SELECT * FROM users WHERE username = 'admin'")
    assert res_sql["is_verified"] is False

    res_py = generator.generate_patch(
        "def get_user_by_username(cursor, username: str):\n"
        "    cursor.execute('SELECT * FROM users WHERE username = ' + username)\n"
    )
    assert res_py["is_verified"] is False


def test_continuous_evaluation_auto_verify():
    """Test full continuous evaluation pipeline with auto_verify=True."""
    orig_code = (
        "def get_user_by_username(cursor, username: str):\n"
        "    query = \"SELECT id, username, role, email FROM users WHERE username = '\" + username + \"'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )

    req = ContinuousEvaluationRequest(
        source_code=orig_code,
        source_revision=2,
        patch_revision=1,
        auto_verify=True,
    )
    res = continuous_evaluate(req)

    assert res.source_revision == 2
    assert res.is_stale is False
    assert res.analysis.is_vulnerable is True
    assert res.generated_patch is not None
    assert res.verification_result is not None
    assert res.verification_result.verdict == Verdict.VERIFIED
    assert res.status == "VERIFIED_VERIFIED"
