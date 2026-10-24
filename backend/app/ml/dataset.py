"""
Curated Training & Evaluation Dataset for Moriarty SQL Injection ML Analyzer.

Contains labeled, non-leaking, realistic Python/SQLite and raw SQL code samples:
- label 1: Vulnerable (dynamic construction, string interpolation, missing parameterization, naive sanitization)
- label 0: Safe (parameterized queries, static queries, validated inputs)
"""

from typing import NamedTuple


class CodeSample(NamedTuple):
    code: str
    label: int  # 1 = Vulnerable, 0 = Safe
    category: str
    description: str


DATASET: list[CodeSample] = [
    # -------------------------------------------------------------------------
    # 1. Vulnerable: String Concatenation (+)
    # -------------------------------------------------------------------------
    CodeSample(
        code="""def get_user(cursor, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()""",
        label=1,
        category="CONCATENATION",
        description="Direct single-quote string concatenation in WHERE clause.",
    ),
    CodeSample(
        code="""def search_products(cursor, term):
    sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + term + "%'"
    cursor.execute(sql)
    return cursor.fetchall()""",
        label=1,
        category="CONCATENATION",
        description="String concatenation inside LIKE wildcard pattern.",
    ),
    CodeSample(
        code="""def find_by_email(cursor, email):
    cursor.execute("SELECT id FROM accounts WHERE email = '" + email + "' AND active = 1")
    return cursor.fetchone()""",
        label=1,
        category="CONCATENATION",
        description="Inline concatenation with trailing condition.",
    ),
    CodeSample(
        code="""def lookup_order(cursor, order_id):
    query = "SELECT * FROM orders WHERE id = " + str(order_id)
    cursor.execute(query)
    return cursor.fetchall()""",
        label=1,
        category="CONCATENATION",
        description="Unquoted numeric concatenation vulnerable to stacked or boolean injection.",
    ),
    CodeSample(
        code="""def filter_users(cursor, role, status):
    base = "SELECT * FROM users WHERE role = '" + role + "'"
    if status:
        base += " AND status = '" + status + "'"
    cursor.execute(base)
    return cursor.fetchall()""",
        label=1,
        category="CONCATENATION",
        description="Dynamic string accumulation across control branches.",
    ),
    CodeSample(
        code="""def authenticate(cursor, user, pwd):
    stmt = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pwd + "'"
    cursor.execute(stmt)
    return cursor.fetchone()""",
        label=1,
        category="CONCATENATION",
        description="Authentication bypass vulnerability via concatenated credentials.",
    ),

    # -------------------------------------------------------------------------
    # 2. Vulnerable: Python F-Strings (f"...")
    # -------------------------------------------------------------------------
    CodeSample(
        code="""def get_user_by_username(cursor, username: str):
    query = f"SELECT id, username, role, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()""",
        label=1,
        category="F_STRING",
        description="Standard f-string embedding username into SQL literal.",
    ),
    CodeSample(
        code="""def get_account_balance(cursor, account_num):
    cursor.execute(f"SELECT balance FROM accounts WHERE account_id = '{account_num}'")
    return cursor.fetchone()""",
        label=1,
        category="F_STRING",
        description="Inline f-string in cursor execute call.",
    ),
    CodeSample(
        code="""def query_inventory(cursor, sku, warehouse):
    q = f"SELECT qty FROM stock WHERE sku = '{sku}' AND loc = '{warehouse}'"
    cursor.execute(q)
    return cursor.fetchall()""",
        label=1,
        category="F_STRING",
        description="Multi-variable f-string SQL query construction.",
    ),
    CodeSample(
        code="""def delete_user(cursor, user_id):
    sql = f"DELETE FROM users WHERE id = {user_id}"
    cursor.execute(sql)""",
        label=1,
        category="F_STRING",
        description="F-string numeric parameter interpolation without quotes.",
    ),
    CodeSample(
        code="""def list_by_department(cursor, dept):
    return cursor.execute(f"SELECT * FROM staff WHERE dept = '{dept}' ORDER BY name").fetchall()""",
        label=1,
        category="F_STRING",
        description="One-liner return with f-string query execution.",
    ),

    # -------------------------------------------------------------------------
    # 3. Vulnerable: String Formatting (% and .format())
    # -------------------------------------------------------------------------
    CodeSample(
        code="""def find_user_legacy(cursor, username):
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    return cursor.fetchall()""",
        label=1,
        category="PERCENT_FORMAT",
        description="Classic %s format string interpolation into SQL literal.",
    ),
    CodeSample(
        code="""def check_login(cursor, u, p):
    sql = "SELECT id FROM members WHERE user = '%s' AND pass = '%s'" % (u, p)
    cursor.execute(sql)
    return cursor.fetchone()""",
        label=1,
        category="PERCENT_FORMAT",
        description="Multiple %s tuple formatting into authentication query.",
    ),
    CodeSample(
        code="""def search_by_keyword(cursor, kw):
    stmt = "SELECT title, body FROM posts WHERE body LIKE '%{}%'".format(kw)
    cursor.execute(stmt)
    return cursor.fetchall()""",
        label=1,
        category="STR_FORMAT",
        description="str.format() injection in LIKE pattern.",
    ),
    CodeSample(
        code="""def get_profile(cursor, uid):
    query = "SELECT * FROM profiles WHERE user_id = {0}".format(uid)
    cursor.execute(query)
    return cursor.fetchone()""",
        label=1,
        category="STR_FORMAT",
        description="str.format() positional argument interpolation for numeric ID.",
    ),

    # -------------------------------------------------------------------------
    # 4. Vulnerable: Flawed / Incomplete Sanitizers (Must be detected as vulnerable)
    # -------------------------------------------------------------------------
    CodeSample(
        code="""def get_user_by_username(cursor, username: str):
    sanitized = username.replace('--', '')
    query = "SELECT id, username, role, email FROM users WHERE username = '" + sanitized + "'"
    cursor.execute(query)
    return cursor.fetchall()""",
        label=1,
        category="FLAWED_SANITIZATION",
        description="Flawed patch: strips comment delimiter '--' but leaves single quotes exploitable.",
    ),
    CodeSample(
        code="""def query_user(cursor, username):
    clean = username.replace("'", "")
    # Vulnerable because escaped quotes or other delimiters can bypass
    sql = "SELECT * FROM users WHERE username = '" + clean + "'"
    cursor.execute(sql)
    return cursor.fetchall()""",
        label=1,
        category="FLAWED_SANITIZATION",
        description="Incomplete string replace without parameterization.",
    ),
    CodeSample(
        code="""def filter_records(cursor, val):
    val = val.strip()
    return cursor.execute("SELECT * FROM data WHERE tag = '" + val + "'").fetchall()""",
        label=1,
        category="FLAWED_SANITIZATION",
        description="Whitespace strip does not neutralize SQL metacharacters.",
    ),

    # -------------------------------------------------------------------------
    # 5. Vulnerable: Raw SQL Strings
    # -------------------------------------------------------------------------
    CodeSample(
        code="SELECT id, username, role, email FROM users WHERE username = 'admin' OR '1'='1'",
        label=1,
        category="RAW_SQL_TAUTOLOGY",
        description="Raw SQL boolean injection tautology in WHERE clause.",
    ),
    CodeSample(
        code="SELECT * FROM accounts WHERE user = 'test' UNION SELECT id, password, 1, 2 FROM admin_users",
        label=1,
        category="RAW_SQL_UNION",
        description="Raw SQL UNION SELECT payload targeting admin credentials.",
    ),
    CodeSample(
        code="SELECT * FROM items WHERE category = 'books' AND 1=1 -- and status = 1",
        label=1,
        category="RAW_SQL_COMMENT",
        description="Raw SQL query truncated using comment marker.",
    ),

    # =========================================================================
    # 6. Safe: Parameterized SQLite Tuple Binding (? placeholder)
    # =========================================================================
    CodeSample(
        code="""def get_user(cursor, username):
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchall()""",
        label=0,
        category="PARAMETERIZED_TUPLE",
        description="Gold standard parameterized query with single element tuple argument.",
    ),
    CodeSample(
        code="""def get_user_by_username(cursor, username: str):
    query = "SELECT id, username, role, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()""",
        label=0,
        category="PARAMETERIZED_TUPLE",
        description="Parameterized query with explicitly typed arguments and separate tuple binding.",
    ),
    CodeSample(
        code="""def search_products(cursor, term):
    pattern = f"%{term}%"
    cursor.execute(
        "SELECT id, name, price FROM products WHERE name LIKE ?",
        (pattern,),
    )
    return cursor.fetchall()""",
        label=0,
        category="PARAMETERIZED_TUPLE",
        description="Safe LIKE pattern search with wildcard parameter passed as data binding.",
    ),
    CodeSample(
        code="""def find_by_email_and_role(cursor, email, role):
    cursor.execute(
        "SELECT id FROM accounts WHERE email = ? AND role = ?",
        (email, role),
    )
    return cursor.fetchone()""",
        label=0,
        category="PARAMETERIZED_TUPLE",
        description="Multi-parameter SQLite placeholder query binding.",
    ),
    CodeSample(
        code="""def lookup_order(cursor, order_id: int):
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    return cursor.fetchall()""",
        label=0,
        category="PARAMETERIZED_TUPLE",
        description="Parameterized numeric integer lookup.",
    ),
    CodeSample(
        code="""def authenticate(cursor, user, pwd):
    stmt = "SELECT id, username FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(stmt, (user, pwd))
    return cursor.fetchone()""",
        label=0,
        category="PARAMETERIZED_TUPLE",
        description="Safe parameterized authentication credential query.",
    ),

    # -------------------------------------------------------------------------
    # 7. Safe: Parameterized Named Placeholders (:name)
    # -------------------------------------------------------------------------
    CodeSample(
        code="""def get_account_balance(cursor, account_num):
    cursor.execute(
        "SELECT balance FROM accounts WHERE account_id = :acc",
        {"acc": account_num},
    )
    return cursor.fetchone()""",
        label=0,
        category="PARAMETERIZED_NAMED",
        description="Named SQLite placeholder using dictionary binding.",
    ),
    CodeSample(
        code="""def filter_users(cursor, role, status):
    query = "SELECT * FROM users WHERE role = :role AND status = :status"
    cursor.execute(query, {"role": role, "status": status})
    return cursor.fetchall()""",
        label=0,
        category="PARAMETERIZED_NAMED",
        description="Named dictionary parameter binding for multiple criteria.",
    ),

    # -------------------------------------------------------------------------
    # 8. Safe: Static Queries Without Metacharacter Manipulation
    # -------------------------------------------------------------------------
    CodeSample(
        code="""def list_all_active_users(cursor):
    cursor.execute("SELECT id, username, role FROM users WHERE active = 1 ORDER BY id ASC")
    return cursor.fetchall()""",
        label=0,
        category="STATIC_QUERY",
        description="Completely static SQL query without external variable input.",
    ),
    CodeSample(
        code="""def get_system_status(cursor):
    return cursor.execute("SELECT count(*) FROM health_check WHERE status = 'OK'").fetchone()""",
        label=0,
        category="STATIC_QUERY",
        description="Static query evaluating hardcoded literal 'OK'.",
    ),
    CodeSample(
        code="""def get_table_schema(cursor):
    cursor.execute("PRAGMA table_info(users)")
    return cursor.fetchall()""",
        label=0,
        category="STATIC_QUERY",
        description="Static PRAGMA introspection query.",
    ),

    # -------------------------------------------------------------------------
    # 9. Safe: Input Validation & Whitelist Logic Combined with Parameterization
    # -------------------------------------------------------------------------
    CodeSample(
        code="""def get_sorted_users(cursor, sort_col, direction):
    allowed_cols = {"id", "username", "created_at"}
    allowed_dir = {"ASC", "DESC"}
    if sort_col not in allowed_cols or direction not in allowed_dir:
        raise ValueError("Invalid sort parameter")
    # Identifiers validated against strict whitelist
    query = f"SELECT id, username FROM users ORDER BY {sort_col} {direction}"
    cursor.execute(query)
    return cursor.fetchall()""",
        label=0,
        category="WHITELIST_IDENTIFIER",
        description="Validated identifier whitelist preventing syntax injection.",
    ),
    CodeSample(
        code="""def update_user_status(cursor, user_id: int, new_status: str):
    valid_statuses = ('ACTIVE', 'SUSPENDED', 'PENDING')
    if new_status not in valid_statuses:
        raise ValueError("Invalid status")
    cursor.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, int(user_id)))""",
        label=0,
        category="PARAMETERIZED_UPDATE",
        description="Validated state and parameterized UPDATE query.",
    ),
    CodeSample(
        code="""def insert_audit_log(cursor, event_type, details):
    cursor.execute(
        "INSERT INTO audit_logs (event, details, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        (event_type, details),
    )""",
        label=0,
        category="PARAMETERIZED_INSERT",
        description="Parameterized INSERT statement protecting event payload.",
    ),
    CodeSample(
        code="""def get_user_orders(cursor, username):
    cursor.execute("SELECT o.id, o.amount FROM orders o JOIN users u ON o.user_id = u.id WHERE u.username = ?", (username,))
    return cursor.fetchall()""",
        label=0,
        category="PARAMETERIZED_JOIN",
        description="Parameterized join query.",
    ),
    CodeSample(
        code="""def query_by_tag(cursor, tag_name):
    stmt = "SELECT id, title FROM articles WHERE tag = ?"
    return cursor.execute(stmt, (tag_name,)).fetchall()""",
        label=0,
        category="PARAMETERIZED_TUPLE",
        description="Parameterized query with clean tuple binding.",
    ),
    CodeSample(
        code="""def fetch_customer_records(cursor, cust_id):
    sql = "SELECT * FROM customers WHERE id = ?"
    cursor.execute(sql, (int(cust_id),))
    return cursor.fetchone()""",
        label=0,
        category="PARAMETERIZED_NUMERIC",
        description="Explicit int cast and parameterized placeholder.",
    ),
    CodeSample(
        code="""def update_email(cursor, user_id, new_email):
    query = "UPDATE users SET email = ? WHERE id = ?"
    cursor.execute(query, (new_email, user_id))""",
        label=0,
        category="PARAMETERIZED_UPDATE",
        description="Safe dual-parameter update statement.",
    ),
    CodeSample(
        code="SELECT id, username, role FROM users WHERE username = ?",
        label=0,
        category="RAW_SQL_PARAMETERIZED",
        description="Raw SQL string with standard ? parameter placeholder.",
    ),
    CodeSample(
        code="SELECT * FROM products WHERE category = :cat AND price < :max_p",
        label=0,
        category="RAW_SQL_NAMED",
        description="Raw SQL query with named placeholders :cat and :max_p.",
    ),
    # Additional Vulnerable Cases
    CodeSample(
        code="""def search_articles(cursor, query):
    return cursor.execute("SELECT * FROM articles WHERE title LIKE '%" + query + "%'").fetchall()""",
        label=1,
        category="CONCATENATION",
        description="Concatenated string search in LIKE condition.",
    ),
    CodeSample(
        code="""def get_admin_dashboard(cursor, role_filter):
    q = f"SELECT * FROM admin_logs WHERE role = '{role_filter}'"
    cursor.execute(q)
    return cursor.fetchall()""",
        label=1,
        category="F_STRING",
        description="F-string injection into administrative audit query.",
    ),
    CodeSample(
        code="""def find_by_phone(cursor, phone_num):
    cursor.execute("SELECT name FROM contacts WHERE phone = '%s'" % phone_num)
    return cursor.fetchone()""",
        label=1,
        category="PERCENT_FORMAT",
        description="Percent-s formatting in phone search.",
    ),
]


def get_dataset() -> list[CodeSample]:
    """Return the complete curated training and validation dataset."""
    return list(DATASET)
