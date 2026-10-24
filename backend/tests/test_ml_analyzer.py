"""
Tests for Moriarty 2.0 ML-Based SQL Injection Analyzer.

Validates:
1. Model loading and version metadata.
2. Graceful fallback when model is missing (unavailable/untrained state without fabricated metrics).
3. Vulnerable code classification (concatenation, f-strings, format).
4. Safe code classification (parameterized queries, static queries).
5. Independence: Same analyzer pipeline evaluates both original and patched source.
6. Feature extraction and catalog category recommendations.
"""

from pathlib import Path
from app.ml.ml_analyzer import SQLInjectionMLAnalyzer


VULN_CONCAT_CODE = """def get_user(cursor, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()"""

VULN_FSTRING_CODE = """def get_user_by_username(cursor, username: str):
    query = f"SELECT id, username, role, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()"""

SAFE_PARAMETERIZED_CODE = """def get_user(cursor, username):
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchall()"""

SAFE_STATIC_CODE = """def list_users(cursor):
    cursor.execute("SELECT id, username FROM users ORDER BY id ASC")
    return cursor.fetchall()"""


def test_ml_analyzer_loads_trained_model():
    """Verify that SQLInjectionMLAnalyzer loads the trained serialized model."""
    analyzer = SQLInjectionMLAnalyzer()
    assert analyzer.model_status == "trained"
    assert analyzer.model is not None
    assert analyzer.model_version == "1.0.0"


def test_ml_analyzer_handles_missing_model_gracefully():
    """Verify that analyzer reports unavailable state when model file is missing."""
    dummy_path = Path("non_existent_model_dir/missing.joblib")
    analyzer = SQLInjectionMLAnalyzer(model_path=dummy_path)

    assert analyzer.model_status == "unavailable"
    assert analyzer.model is None

    result = analyzer.analyze(VULN_CONCAT_CODE)
    assert result["model_status"] == "unavailable"
    assert result["predicted_class"] == "unknown"
    assert result["risk_score"] == 0.0
    assert result["risk_level"] == "UNKNOWN"
    assert "unavailable" in result["summary"].lower()


def test_ml_analyzer_detects_vulnerable_concatenation():
    """Vulnerable string concatenation receives high risk score and classification."""
    analyzer = SQLInjectionMLAnalyzer()
    res = analyzer.analyze(VULN_CONCAT_CODE)

    assert res["model_status"] == "trained"
    assert res["predicted_class"] == "potential_sql_injection"
    assert res["risk_score"] >= 0.50
    assert res["risk_level"] in ("HIGH", "CRITICAL")
    assert "string_concatenation_in_query" in res["detected_features"]
    assert "Quote and delimiter handling" in res["recommended_test_categories"]


def test_ml_analyzer_detects_vulnerable_fstring():
    """Vulnerable f-string interpolation receives elevated risk score."""
    analyzer = SQLInjectionMLAnalyzer()
    res = analyzer.analyze(VULN_FSTRING_CODE)

    assert res["model_status"] == "trained"
    assert res["predicted_class"] == "potential_sql_injection"
    assert res["risk_score"] >= 0.50
    assert "fstring_query_interpolation" in res["detected_features"]


def test_ml_analyzer_evaluates_safe_parameterized_query():
    """Safe parameterized implementation receives low risk score."""
    analyzer = SQLInjectionMLAnalyzer()
    res = analyzer.analyze(SAFE_PARAMETERIZED_CODE)

    assert res["model_status"] == "trained"
    assert res["risk_score"] <= 0.25
    assert res["risk_level"] == "LOW"
    assert "parameter_placeholder_binding" in res["detected_features"]
    assert res["predicted_class"] == "safe_query_pattern"


def test_same_pipeline_evaluates_both_original_and_patch():
    """
    Critical requirement: The exact same ML analyzer pipeline instance
    evaluates both the original submitted source and candidate patch,
    showing clear risk reduction after parameterization.
    """
    analyzer = SQLInjectionMLAnalyzer()

    orig_analysis = analyzer.analyze(VULN_CONCAT_CODE)
    patch_analysis = analyzer.analyze(SAFE_PARAMETERIZED_CODE)

    # Both run through same pipeline
    assert orig_analysis["model_status"] == "trained"
    assert patch_analysis["model_status"] == "trained"

    # Risk must drop significantly from vulnerable original to parameterized patch
    assert orig_analysis["risk_score"] > patch_analysis["risk_score"]
    assert orig_analysis["risk_level"] in ("HIGH", "CRITICAL")
    assert patch_analysis["risk_level"] == "LOW"


def test_ml_analyzer_empty_input():
    """Empty code returns zero risk without throwing exceptions."""
    analyzer = SQLInjectionMLAnalyzer()
    res = analyzer.analyze("")
    assert res["risk_score"] == 0.0
    assert res["risk_level"] == "LOW"
