"""
Regression scenario for Moriarty.
Static query without parameters where input is ignored or breaks required functionality.
"""

import sqlite3
from typing import Any


SOURCE_CODE = '''def get_user_by_username(cursor, username: str):
    cursor.execute("SELECT id, username, role, email FROM users WHERE id = 1")
    return cursor.fetchall()
'''


class RegressionUserApp:
    """
    App that replaces the query with a static query ignoring username.
    This breaks basic functionality (cannot look up bob).
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
        # Hardcoded static query: ignores username parameter
        cursor.execute("SELECT id, username, role, email FROM users WHERE id = 1")
        rows = cursor.fetchall()
        return [
            {"id": r[0], "username": r[1], "role": r[2], "email": r[3]}
            for r in rows
        ]

    def close(self) -> None:
        if self.connection:
            self.connection.close()
