
from app.verification.patch_comparator import PatchComparator

original = """
def get_user(cursor, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
"""

patched = """
def get_user(cursor, username):
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    )
"""

result = PatchComparator().compare(original, patched)

print("Status:", result.status)
print("Summary:", result.summary)
print("Original findings:", result.original_rule_ids)
print("Patched findings:", result.patched_rule_ids)
print("Static improvement:", result.static_improvement_detected)
print("Dynamic verification:", result.dynamic_verification_performed)
