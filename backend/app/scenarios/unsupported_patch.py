"""
Unsupported syntax scenario for Moriarty.
Contains syntax error that prevents static AST analysis.
"""

SOURCE_CODE = """def get_user_by_username(cursor, username: str):
    query = "SELECT * FROM users"
    cursor.execute(query
    # Syntax error: unclosed parenthesis
"""
