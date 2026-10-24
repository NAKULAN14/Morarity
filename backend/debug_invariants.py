from app.analyzer.ast_analyzer import analyze_sql_injection
from app.analyzer.invariants import generate_invariants

source = """
def get_user(cursor, query):
    cursor.execute(query)
"""

analysis = analyze_sql_injection(source)

print("FINDING IDS:")
for finding in analysis.findings:
    print(finding.rule_id)

print("\nGENERATED INVARIANTS:")
for invariant in generate_invariants(analysis):
    print(invariant)