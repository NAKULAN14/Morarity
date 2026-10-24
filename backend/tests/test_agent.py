import json
from app.agent.agent_loop import MoriartyAgentLoop
from app.models.schemas import Verdict
from app.scenarios.correct_patch import PatchedUserApp
from app.scenarios.incomplete_patch import IncompletePatchUserApp, SOURCE_CODE as INCOMPLETE_SOURCE
from app.scenarios.vulnerable import VulnerableUserApp


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


def test_agent_loop_preserves_inconclusive_verdict(tmp_path):
    report_path = tmp_path / "moriarty_report.json"

    agent = MoriartyAgentLoop(max_tests=3)

    result = agent.run(
        original_source=VULNERABLE_SOURCE,
        patched_source=PATCHED_SOURCE,
        report_path=str(report_path),
    )

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.final_action == "STOP_INCONCLUSIVE"
    assert result.patch_comparison is not None
    assert result.patch_comparison.status == "PATCH_PATTERN_IMPROVED"

    assert len(result.tests_executed) == 3
    assert all(test.passed for test in result.tests_executed)

    assert report_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["verdict"] == "INCONCLUSIVE"
    assert report["agent"]["tests_run"] == 3

    assert (
        report["analysis"]["findings"][0]["rule_id"]
        == "SQLI_PARAMETERIZED_QUERY"
    )

    assert (
        report["patch_comparison"]["original_analysis"]["findings"][0][
            "rule_id"
        ]
        == "SQLI_UNSAFE_QUERY"
    )


def test_agent_loop_verifies_real_local_patched_application(tmp_path):
    """
    Validates end-to-end VERIFIED workflow against real local SQLite application.
    Checks Requirements 5, 6, 7, 8, 9, 12, 14.
    """
    report_path = tmp_path / "verified_report.json"
    vuln_app = VulnerableUserApp()
    patch_app = PatchedUserApp()

    try:
        agent = MoriartyAgentLoop(max_tests=3)
        result = agent.run(
            original_source=vuln_app.source_code,
            patched_source=patch_app.source_code,
            vulnerable_app=vuln_app,
            patched_app=patch_app,
            report_path=str(report_path),
        )

        assert result.verdict == Verdict.VERIFIED
        assert result.dynamic_verification_performed is True
        assert result.target_type == "REAL_LOCAL_APPLICATION"
        assert len(result.tests_executed) == 3
        assert all(t.passed for t in result.tests_executed)

        # Validate decision trace
        assert result.decision_trace is not None
        assert len(result.decision_trace) >= 3
        trace_step = result.decision_trace[0]
        assert "step" in trace_step
        assert "action" in trace_step
        assert "strategy" in trace_step
        assert "reason" in trace_step
        assert "test_outcome" in trace_step
        assert "evidence_id" in trace_step

        # Validate report output
        assert report_path.exists()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["verdict"] == "VERIFIED"
        assert report["dynamic_verification_performed"] is True
        assert "verification_scope" in report
        assert len(report["limitations"]) > 0
        assert "decision_trace" in report["agent"]

    finally:
        vuln_app.close()
        patch_app.close()


def test_agent_loop_rejects_incomplete_patch(tmp_path):
    """
    Validates end-to-end REJECTED workflow when testing an incomplete patch.
    Checks Requirements 6, 8, 12.
    """
    report_path = tmp_path / "rejected_report.json"
    vuln_app = VulnerableUserApp()
    incomplete_app = IncompletePatchUserApp()

    try:
        agent = MoriartyAgentLoop(max_tests=3)
        result = agent.run(
            original_source=vuln_app.source_code,
            patched_source=incomplete_app.source_code,
            vulnerable_app=vuln_app,
            patched_app=incomplete_app,
            report_path=str(report_path),
        )

        assert result.verdict == Verdict.REJECTED
        assert result.final_action == "STOP_REJECTED"
        assert report_path.exists()

        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["verdict"] == "REJECTED"
        assert "remains exploitable" in report["summary"].lower()

    finally:
        vuln_app.close()
        incomplete_app.close()


def test_agent_loop_handles_unsupported_source(tmp_path):
    """
    Validates end-to-end INCONCLUSIVE workflow when source cannot be analyzed.
    """
    report_path = tmp_path / "unsupported_report.json"
    agent = MoriartyAgentLoop(max_tests=3)

    result = agent.run(
        original_source=VULNERABLE_SOURCE,
        patched_source="def broken(:",
        report_path=str(report_path),
    )

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.final_action == "STOP_INCONCLUSIVE"
    assert result.patch_comparison.status == "ANALYSIS_UNSUPPORTED"
