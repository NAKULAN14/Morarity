from app.execution.differential_runner import DifferentialSQLRunner
from app.verification.evidence_ledger import EvidenceLedger

runner = DifferentialSQLRunner()
test_result = runner.run_as_test_result()

ledger = EvidenceLedger()
evidence = ledger.record(test_result)

print("Test result:", test_result)
print("Evidence:", evidence)