from app.analyzer.ast_analyzer import analyze_sql_injection

source = """
def get_user(cursor, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"""

result = analyze_sql_injection(source)

for finding in result.findings:
    print(finding.rule_id, finding.message)