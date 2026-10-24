
from app.agent.agent_loop import MoriartyAgentLoop


original_code = """
def get_user(cursor, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
"""


patched_code = """
def get_user(cursor, username):
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    )
"""


agent = MoriartyAgentLoop()

result = agent.run(
    original_source=original_code,
    patched_source=patched_code,
)

print("\n========== MORIARTY RESULT ==========")

print("Final action:", result.final_action)
print("Final verdict:", result.verdict.value)
print("Verdict summary:", result.verdict_summary)

if result.patch_comparison:
    print("\nPatch comparison:")
    print("Status:", result.patch_comparison.status)
    print("Summary:", result.patch_comparison.summary)
    print(
        "Static improvement:",
        result.patch_comparison.static_improvement_detected,
    )
