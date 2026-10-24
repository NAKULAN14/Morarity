"""
Tests for LocalAppVerificationRunner and actual local SQLite application behavior.
Validates Requirements 7 & 8: Real local application behavior and vulnerable-vs-patched distinction.
"""

from app.execution.local_app_runner import LocalAppVerificationRunner
from app.scenarios.correct_patch import PatchedUserApp
from app.scenarios.incomplete_patch import IncompletePatchUserApp
from app.scenarios.vulnerable import VulnerableUserApp


def test_vulnerable_app_leaks_records_on_injection():
    app = VulnerableUserApp()
    try:
        # Benign search
        benign = app.search_users("alice")
        assert len(benign) == 1
        assert benign[0]["username"] == "alice"

        # SQL Injection search
        injected = app.search_users("' OR '1'='1")
        # Should return all 3 users in database
        assert len(injected) == 3
        assert {u["username"] for u in injected} == {"alice", "bob", "charlie"}
    finally:
        app.close()


def test_patched_app_neutralizes_injection_and_preserves_functionality():
    app = PatchedUserApp()
    try:
        # Benign search preserves functionality
        benign = app.search_users("alice")
        assert len(benign) == 1
        assert benign[0]["username"] == "alice"

        # SQL Injection search is treated as literal parameter string
        injected = app.search_users("' OR '1'='1")
        assert len(injected) == 0

        # Comment injection search is treated as literal parameter
        comment_injected = app.search_users("admin' OR 1=1 --")
        assert len(comment_injected) == 0
    finally:
        app.close()


def test_differential_runner_distinguishes_vulnerable_and_patched():
    vuln_app = VulnerableUserApp()
    patch_app = PatchedUserApp()
    try:
        runner = LocalAppVerificationRunner(vuln_app, patch_app)
        result = runner.run_test(payload="' OR '1'='1", test_id="TEST_001")

        assert result.passed is True
        assert result.outcome == "PASS"
        assert result.baseline_exploitable is True
        assert result.patch_blocks_payload is True
        assert result.functionality_intact is True
        assert result.target_type == "REAL_LOCAL_APPLICATION"
        assert len(result.vulnerable_rows) == 3
        assert len(result.patched_rows) == 0
        assert result.execution_time_ms >= 0
    finally:
        vuln_app.close()
        patch_app.close()


def test_incomplete_patch_fails_differential_test():
    """Validates incomplete patch detection (Requirement 6)."""
    vuln_app = VulnerableUserApp()
    incomplete_app = IncompletePatchUserApp()
    try:
        runner = LocalAppVerificationRunner(vuln_app, incomplete_app)
        result = runner.run_test(payload="' OR '1'='1", test_id="TEST_INCOMPLETE")

        assert result.passed is False
        assert result.outcome == "FAIL"
        assert result.baseline_exploitable is True
        assert result.patch_blocks_payload is False  # Incomplete patch leaked rows
        assert len(result.patched_rows) == 3
        assert "REJECTED" in result.details
    finally:
        vuln_app.close()
        incomplete_app.close()


def test_runner_handles_exception_safely():
    """Validates runner error handling (Requirement 11)."""
    class CrashingApp:
        def search_users(self, username):
            raise RuntimeError("Database connection severed")

    runner = LocalAppVerificationRunner(CrashingApp(), PatchedUserApp())
    result = runner.run_test(payload="' OR '1'='1")

    assert result.passed is False
    assert result.outcome == "ERROR"
    assert result.error is not None
    assert "Database connection severed" in result.error
