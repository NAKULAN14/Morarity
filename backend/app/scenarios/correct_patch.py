"""
Correctly patched SQLite application scenario for Moriarty.
Uses parameterized queries to prevent SQL structure alteration.
"""

import sqlite3
from typing import Any


SOURCE_CODE = '''def get_user_by_username(cursor, username: str):
    cursor.execute(
        "SELECT id, username, role, email FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchall()
'''


class PatchedUserApp:
    """
    Properly patched local SQLite application.
    Executes parameterized queries passing untrusted input as a bound parameter.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self.source_code = SOURCE_CODE
        self.db_path = db_path
        self.connection = sqlite3.connect(self.db_path)
        self._init_db()

    def _init_db(self) -> None:
        cursor = self.connection.cursor()
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL
            )
            """
        )
        cursor.executemany(
            "INSERT INTO users (id, username, role, email) VALUES (?, ?, ?, ?)",
            [
                (1, "alice", "user", "alice@example.local"),
                (2, "bob", "user", "bob@example.local"),
                (3, "charlie", "admin", "charlie@example.local"),
            ],
        )
        self.connection.commit()

    def search_users(self, username: str) -> list[dict[str, Any]]:
        cursor = self.connection.cursor()
        # Safe parameterized execution matching SOURCE_CODE
        cursor.execute(
            "SELECT id, username, role, email FROM users WHERE username = ?",
            (username,),
        )
        rows = cursor.fetchall()
        return [
            {"id": r[0], "username": r[1], "role": r[2], "email": r[3]}
            for r in rows
        ]

    def close(self) -> None:
        if self.connection:
            self.connection.close()
