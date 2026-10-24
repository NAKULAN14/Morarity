"""
Tests for VerdictEngine three-outcome model and verification invariant integrity.
"""

from app.models.schemas import Evidence, Verdict
from app.verification.verdict_engine import VerdictEngine


def test_empty_evidence_produces_inconclusive():
    engine = VerdictEngine()
    verdict, summary = engine.decide([])
    assert verdict == Verdict.INCONCLUSIVE
    assert "No evidence" in summary


def test_controlled_fixture_cannot_produce_false_verified():
    """Requirement 13: Controlled fixtures cannot produce false verification."""
    engine = VerdictEngine()

    fixture_evidence = [
        Evidence(
            evidence_id="demo-1",
            test_id="SQLI_DIFFERENTIAL_001",
            category="CONTROLLED_DEMONSTRATION",
            description="Simulated fixture passed",
            observed={"outcome": "PASS", "passed": True, "error": None},
            supports_verification=False,
        ),
        Evidence(
            evidence_id="demo-2",
            test_id="SQLI_DIFFERENTIAL_002",
            category="CONTROLLED_DEMONSTRATION",
            description="Simulated fixture passed",
            observed={"outcome": "PASS", "passed": True, "error": None},
            supports_verification=False,
        ),
    ]

    verdict, summary = engine.decide(fixture_evidence)
    assert verdict == Verdict.INCONCLUSIVE
    assert "controlled demonstration" in summary.lower()
    assert verdict != Verdict.VERIFIED


def test_real_application_verification_produces_verified_with_scope():
    """Requirement 12: Correct VERIFIED outcome with explicit scope."""
    engine = VerdictEngine()

    real_evidence = [
        Evidence(
            evidence_id="real-1",
            test_id="SQLI_REAL_001",
            category="REAL_APPLICATION_VERIFICATION",
            description="Payload neutralized on real app",
            observed={
                "outcome": "PASS",
                "passed": True,
                "baseline_exploitable": True,
                "patch_blocks_payload": True,
                "functionality_intact": True,
                "source_runtime_match": True,
                "submitted_source_executed": True,
                "target_type": "REAL_LOCAL_APPLICATION",
                "target_provenance": "RESTRICTED_SOURCE_ENV",
                "verification_scope": "Targeted local SQLite query construction path",
                "error": None,
            },
            supports_verification=True,
        ),
        Evidence(
            evidence_id="real-2",
            test_id="SQLI_REAL_002",
            category="REAL_APPLICATION_VERIFICATION",
            description="Comment payload neutralized on real app",
            observed={
                "outcome": "PASS",
                "passed": True,
                "baseline_exploitable": True,
                "patch_blocks_payload": True,
                "functionality_intact": True,
                "source_runtime_match": True,
                "submitted_source_executed": True,
                "target_type": "REAL_LOCAL_APPLICATION",
                "target_provenance": "RESTRICTED_SOURCE_ENV",
                "verification_scope": "Targeted local SQLite query construction path",
                "error": None,
            },
            supports_verification=True,
        ),
    ]

    verdict, summary = engine.decide(real_evidence)
    assert verdict == Verdict.VERIFIED
    assert "Verification scope:" in summary
    assert "targeted" in summary.lower()


def test_incomplete_patch_produces_rejected():
    """Requirement 12: Correct REJECTED outcome when patch fails."""
    engine = VerdictEngine()

    real_evidence = [
        Evidence(
            evidence_id="real-fail-1",
            test_id="SQLI_REAL_001",
            category="REAL_APPLICATION_VERIFICATION",
            description="Payload exploited patched app",
            observed={
                "outcome": "FAIL",
                "passed": False,
                "baseline_exploitable": True,
                "patch_blocks_payload": False,
                "functionality_intact": True,
                "source_runtime_match": True,
                "submitted_source_executed": True,
                "target_type": "REAL_LOCAL_APPLICATION",
                "target_provenance": "RESTRICTED_SOURCE_ENV",
                "verification_scope": "Targeted local SQLite query construction path",
                "error": None,
            },
            supports_verification=False,
        )
    ]

    verdict, summary = engine.decide(real_evidence)
    assert verdict == Verdict.REJECTED
    assert "remains exploitable" in summary


def test_unsupported_analysis_produces_inconclusive():
    engine = VerdictEngine()

    evidence = [
        Evidence(
            evidence_id="stat-1",
            test_id="STATIC_PATCH_COMPARISON",
            category="STATIC_ANALYSIS",
            description="Unsupported syntax",
            observed={"status": "ANALYSIS_UNSUPPORTED"},
            supports_verification=False,
        )
    ]

    verdict, summary = engine.decide(evidence)
    assert verdict == Verdict.INCONCLUSIVE
    assert "unsupported" in summary.lower()


def test_runner_error_produces_inconclusive():
    """Requirement 11: Correct handling of runner errors."""
    engine = VerdictEngine()

    evidence = [
        Evidence(
            evidence_id="err-1",
            test_id="SQLI_REAL_001",
            category="REAL_APPLICATION_VERIFICATION",
            description="Connection error",
            observed={"outcome": "ERROR", "error": "sqlite3.OperationalError: table locked"},
            supports_verification=False,
        )
    ]

    verdict, summary = engine.decide(evidence)
    assert verdict == Verdict.INCONCLUSIVE
    assert "errors" in summary.lower()
