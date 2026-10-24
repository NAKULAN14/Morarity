
from app.verification.evidence_ledger import EvidenceLedger
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


def test_static_comparison_is_recorded_as_non_verifying_evidence():
    comparator = PatchComparator()
    ledger = EvidenceLedger()

    comparison = comparator.compare(
        VULNERABLE_SOURCE,
        PATCHED_SOURCE,
    )

    evidence = ledger.record_patch_comparison(comparison)

    assert evidence.category == "STATIC_ANALYSIS"
    assert evidence.test_id == "STATIC_PATCH_COMPARISON"
    assert evidence.supports_verification is False

    assert evidence.observed["status"] == "PATCH_PATTERN_IMPROVED"
    assert evidence.observed["static_improvement_detected"] is True
    assert evidence.observed["dynamic_verification_performed"] is False

    assert "SQLI_UNSAFE_QUERY" in evidence.observed["original_rule_ids"]
    assert (
        "SQLI_PARAMETERIZED_QUERY"
        in evidence.observed["patched_rule_ids"]
    )

    assert len(ledger.get_all()) == 1
