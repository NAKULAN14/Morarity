"""
Generalized SQLite SQL Parser & Syntax Engine for Moriarty 2.0.

Provides robust syntax validation, statement classification, table/column extraction,
and mock schema synthesis for arbitrary SQLite SQL statements across the full SQLite
language surface (SELECT, INSERT, UPDATE, DELETE, DDL, CTEs, JOINs, PRAGMAs).
"""

import re
import sqlite3
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class SQLiteStatementType(str, Enum):
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    CREATE_TABLE = "CREATE_TABLE"
    ALTER_TABLE = "ALTER_TABLE"
    DROP_TABLE = "DROP_TABLE"
    CREATE_INDEX = "CREATE_INDEX"
    DROP_INDEX = "DROP_INDEX"
    CREATE_VIEW = "CREATE_VIEW"
    DROP_VIEW = "DROP_VIEW"
    CREATE_TRIGGER = "CREATE_TRIGGER"
    DROP_TRIGGER = "DROP_TRIGGER"
    WITH_CTE = "WITH_CTE"
    PRAGMA = "PRAGMA"
    TRANSACTION = "TRANSACTION"
    EXPRESSION = "EXPRESSION"
    OTHER = "OTHER"


@dataclass
class ParsedSQLiteQuery:
    """Structured representation of parsed SQLite statement."""
    raw_query: str
    statement_type: SQLiteStatementType
    is_valid_syntax: bool
    syntax_error: Optional[str] = None
    tables: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    parameter_markers: list[str] = field(default_factory=list)
    literal_predicates: list[dict[str, Any]] = field(default_factory=list)
    is_parameterized: bool = False
    has_dynamic_construction: bool = False
    is_ddl_or_pragma: bool = False
    can_dynamically_verify: bool = True
    verification_limitation: Optional[str] = None


class SQLiteParser:
    """
    Robust SQLite SQL parser and validator leveraging Python's sqlite3 engine
    and structural pattern recognition for arbitrary SQLite statements.
    """

    TABLE_PATTERNS = [
        re.compile(r'\b(?:FROM|INTO|UPDATE|TABLE|JOIN|VIEW)\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.IGNORECASE),
        re.compile(r'\bCREATE\s+(?:INDEX|TRIGGER)\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s+ON\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.IGNORECASE),
    ]

    COLUMN_PATTERNS = [
        # SELECT col1, col2 FROM ...
        re.compile(r'\bSELECT\s+(.+?)\s+\bFROM\b', re.IGNORECASE | re.DOTALL),
        # INSERT INTO tbl (col1, col2) ...
        re.compile(r'\bINSERT\s+INTO\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(([^)]+)\)', re.IGNORECASE),
        # SET col1 = val, col2 = val
        re.compile(r'\bSET\s+(.+?)(?:\s+\bWHERE\b|$)', re.IGNORECASE | re.DOTALL),
        # WHERE col1 = val
        re.compile(r'\bWHERE\s+(.+?)(?:\s+(?:GROUP\s+BY|HAVING|ORDER\s+BY|LIMIT)\b|$)', re.IGNORECASE | re.DOTALL),
    ]

    LITERAL_PREDICATE_REGEX = re.compile(
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(=|!=|<>|LIKE|>|<|>=|<=)\s*(\'([^\']*)\'|"([^"]*)"|(\d+(?:\.\d+)?))',
        re.IGNORECASE,
    )

    PARAM_MARKER_REGEX = re.compile(r'(\?|:[a-zA-Z_][a-zA-Z0-9_]*|@[a-zA-Z_][a-zA-Z0-9_]*|\$[a-zA-Z_][a-zA-Z0-9_]*)')

    @classmethod
    def classify_statement_type(cls, query: str) -> SQLiteStatementType:
        """Identify SQLite statement type from query text."""
        cleaned = query.strip()
        # Remove comments
        cleaned = re.sub(r'--.*?$', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL).strip()
        first_token = (cleaned.split()[0] if cleaned.split() else "").upper()

        if first_token == "SELECT":
            return SQLiteStatementType.SELECT
        elif first_token == "INSERT":
            return SQLiteStatementType.INSERT
        elif first_token == "UPDATE":
            return SQLiteStatementType.UPDATE
        elif first_token == "DELETE":
            return SQLiteStatementType.DELETE
        elif first_token == "WITH":
            return SQLiteStatementType.WITH_CTE
        elif first_token == "PRAGMA":
            return SQLiteStatementType.PRAGMA
        elif first_token == "CREATE":
            second = (cleaned.split()[1] if len(cleaned.split()) > 1 else "").upper()
            if second == "TABLE":
                return SQLiteStatementType.CREATE_TABLE
            elif second in ("INDEX", "UNIQUE"):
                return SQLiteStatementType.CREATE_INDEX
            elif second == "VIEW":
                return SQLiteStatementType.CREATE_VIEW
            elif second == "TRIGGER":
                return SQLiteStatementType.CREATE_TRIGGER
            return SQLiteStatementType.OTHER
        elif first_token == "ALTER":
            return SQLiteStatementType.ALTER_TABLE
        elif first_token == "DROP":
            second = (cleaned.split()[1] if len(cleaned.split()) > 1 else "").upper()
            if second == "TABLE":
                return SQLiteStatementType.DROP_TABLE
            elif second == "INDEX":
                return SQLiteStatementType.DROP_INDEX
            elif second == "VIEW":
                return SQLiteStatementType.DROP_VIEW
            elif second == "TRIGGER":
                return SQLiteStatementType.DROP_TRIGGER
            return SQLiteStatementType.OTHER
        elif first_token in ("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT"):
            return SQLiteStatementType.TRANSACTION
        return SQLiteStatementType.OTHER

    @classmethod
    def extract_tables(cls, query: str) -> list[str]:
        """Extract table names referenced in query."""
        tables: set[str] = set()
        clean = re.sub(r'--.*?$', '', query, flags=re.MULTILINE)
        clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)

        for match in cls.TABLE_PATTERNS[0].finditer(clean):
            tbl = match.group(1).strip()
            # Exclude keywords like IF, NOT, EXISTS
            if tbl.upper() not in ("IF", "NOT", "EXISTS", "INDEX", "TABLE", "VIEW", "TRIGGER", "SELECT", "WHERE", "JOIN"):
                tables.add(tbl)

        for match in cls.TABLE_PATTERNS[1].finditer(clean):
            tbl = match.group(2).strip()
            tables.add(tbl)

        # Discard CTE alias names if defined in WITH
        with_match = re.search(r'\bWITH\s+(?:RECURSIVE\s+)?([a-zA-Z_][a-zA-Z0-9_]*)', clean, re.IGNORECASE)
        if with_match:
            cte_name = with_match.group(1)
            # We still keep the CTE or referenced base tables

        return sorted(tables)

    @classmethod
    def extract_columns(cls, query: str) -> list[str]:
        """Extract referenced column names from SELECT, INSERT, SET, or WHERE clauses."""
        columns: set[str] = set()
        clean = re.sub(r'--.*?$', '', query, flags=re.MULTILINE)
        clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.DOTALL)

        # 1. From INSERT INTO tbl (cols...)
        insert_match = cls.COLUMN_PATTERNS[1].search(clean)
        if insert_match:
            for col in insert_match.group(1).split(","):
                c = col.strip().split()[0].replace('`', '').replace('"', '')
                if c and c.isidentifier():
                    columns.add(c)

        # 2. From SET col = ...
        set_match = cls.COLUMN_PATTERNS[2].search(clean)
        if set_match:
            assignments = set_match.group(1).split(",")
            for assign in assignments:
                parts = assign.split("=")
                if len(parts) >= 1:
                    c = parts[0].strip().replace('`', '').replace('"', '')
                    if c and c.isidentifier():
                        columns.add(c)

        # 3. From WHERE clause predicates (both literal and parameterized)
        where_match = cls.COLUMN_PATTERNS[3].search(clean)
        if where_match:
            where_clause = where_match.group(1)
            predicates = cls.LITERAL_PREDICATE_REGEX.findall(where_clause)
            for col, op, full_val, str_s, str_d, num in predicates:
                c = col.strip().split(".")[-1].replace('`', '').replace('"', '')
                if c and c.isidentifier() and c.upper() not in ("AND", "OR", "NOT", "NULL"):
                    columns.add(c)

            # Match parameterized predicates like col = ?, col LIKE :name, col = $var
            param_preds = re.findall(
                r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(=|!=|<>|LIKE|>|<|>=|<=)\s*(?:\?|:[a-zA-Z_][a-zA-Z0-9_]*|@[a-zA-Z_][a-zA-Z0-9_]*|\$[a-zA-Z_][a-zA-Z0-9_]*)',
                where_clause,
                re.IGNORECASE,
            )
            for col, op in param_preds:
                c = col.strip().split(".")[-1].replace('`', '').replace('"', '')
                if c and c.isidentifier() and c.upper() not in ("AND", "OR", "NOT", "NULL"):
                    columns.add(c)

        # 4. From SELECT col1, col2
        select_match = cls.COLUMN_PATTERNS[0].search(clean)
        if select_match:
            col_clause = select_match.group(1)
            if col_clause.strip() != "*":
                for col_expr in col_clause.split(","):
                    # Check for alias 'AS col' or simple 'table.col'
                    as_match = re.search(r'\bAS\s+([a-zA-Z_][a-zA-Z0-9_]*)', col_expr, re.IGNORECASE)
                    if as_match:
                        columns.add(as_match.group(1))
                    else:
                        c = col_expr.strip().split(".")[-1].replace('`', '').replace('"', '')
                        if c and c.isidentifier() and c.upper() not in ("COUNT", "SUM", "AVG", "MAX", "MIN", "DISTINCT"):
                            columns.add(c)

        # Also extract columns mentioned in JOIN ON or WHERE conditions (e.g. o.user_id, u.id)
        for col_match in re.finditer(r'\b[a-zA-Z_][a-zA-Z0-9_]*\.([a-zA-Z_][a-zA-Z0-9_]*)\b', clean):
            c_name = col_match.group(1)
            if c_name.isidentifier() and c_name.upper() not in ("ID", "AND", "OR", "ON"):
                columns.add(c_name)

        return sorted(columns)

    @classmethod
    def validate_sqlite_syntax(cls, sql: str, tables: list[str], columns: list[str]) -> tuple[bool, Optional[str]]:
        """
        Validate syntax using the native SQLite engine in an isolated connection.
        Dynamically provisions mock tables and columns to evaluate syntax validity.
        Distinguishes true syntax errors ('near "...": syntax error') from
        uninstantiated table/column schema constraints.
        """
        cleaned = sql.strip().rstrip(";")
        if not cleaned:
            return False, "Query string is empty"

        conn = sqlite3.connect(":memory:")
        c = conn.cursor()

        # Provision mock tables for discovered tables so SQLite parser can proceed
        def _provision_table(tbl: str, extra_cols: list[str] = None):
            col_defs = ["id INTEGER PRIMARY KEY"]
            all_cols = set(columns + (extra_cols or []))
            for col in all_cols:
                if col.lower() != "id":
                    col_defs.append(f"{col} TEXT")
            # Always ensure basic fallback columns
            for fallback in ("username", "role", "email", "name", "status", "user_id", "total", "category", "price", "level", "message"):
                if fallback not in all_cols:
                    col_defs.append(f"{fallback} TEXT")
            create_stmt = f"CREATE TABLE IF NOT EXISTS {tbl} ({', '.join(col_defs)})"
            try:
                c.execute(create_stmt)
            except Exception:
                pass

        for tbl in tables or ["users"]:
            _provision_table(tbl)

        stmt_type = cls.classify_statement_type(cleaned)
        attempts = 0
        while attempts < 5:
            attempts += 1
            try:
                if stmt_type in (
                    SQLiteStatementType.CREATE_TABLE,
                    SQLiteStatementType.CREATE_INDEX,
                    SQLiteStatementType.CREATE_VIEW,
                    SQLiteStatementType.CREATE_TRIGGER,
                    SQLiteStatementType.ALTER_TABLE,
                    SQLiteStatementType.DROP_TABLE,
                    SQLiteStatementType.DROP_INDEX,
                    SQLiteStatementType.DROP_VIEW,
                    SQLiteStatementType.DROP_TRIGGER,
                    SQLiteStatementType.PRAGMA,
                ):
                    c.execute(cleaned)
                    conn.rollback()
                else:
                    c.execute(f"EXPLAIN {cleaned}")
                conn.close()
                return True, None
            except (sqlite3.OperationalError, sqlite3.ProgrammingError) as exc:
                err = str(exc)
                if "bindings supplied" in err:
                    conn.close()
                    return True, None
                if "no such table:" in err:
                    missing_tbl = err.split("no such table:")[1].strip().split()[0].replace('"', '').replace("'", "")
                    _provision_table(missing_tbl)
                    continue
                elif "no such column:" in err:
                    missing_col = err.split("no such column:")[1].strip().split()[0].split(".")[-1].replace('"', '').replace("'", "")
                    for tbl in tables or ["users"]:
                        try:
                            c.execute(f"ALTER TABLE {tbl} ADD COLUMN {missing_col} TEXT")
                        except Exception:
                            pass
                    continue
                elif "table" in err and "has no column named" in err:
                    # e.g. table logs has no column named level
                    parts = err.split("has no column named")
                    missing_col = parts[1].strip().split()[0].replace('"', '').replace("'", "")
                    tbl_name = parts[0].replace("table", "").strip().split()[0]
                    try:
                        c.execute(f"ALTER TABLE {tbl_name} ADD COLUMN {missing_col} TEXT")
                    except Exception:
                        pass
                    continue
                else:
                    # If error is a true syntax error (e.g. 'near "?": syntax error')
                    conn.close()
                    if "syntax error" in err or "incomplete input" in err:
                        return False, err
                    # If error is about schema/types but syntax is valid
                    return True, None
            except Exception as exc:
                conn.close()
                return False, str(exc)

        conn.close()
        return True, None

    @classmethod
    def parse_query(cls, sql_text: str) -> ParsedSQLiteQuery:
        """
        Perform complete generalized parsing and classification of a SQLite SQL statement.
        """
        raw = sql_text.strip() if sql_text else ""
        if not raw:
            return ParsedSQLiteQuery(
                raw_query="",
                statement_type=SQLiteStatementType.OTHER,
                is_valid_syntax=False,
                syntax_error="Query is empty",
                can_dynamically_verify=False,
                verification_limitation="Empty query input cannot be analyzed or verified.",
            )

        stmt_type = cls.classify_statement_type(raw)
        tables = cls.extract_tables(raw)
        columns = cls.extract_columns(raw)

        # Check parameter markers
        param_markers = cls.PARAM_MARKER_REGEX.findall(raw)
        is_parameterized = len(param_markers) > 0

        # Check for dynamic concatenation or template markers inside SQL
        has_dynamic = ("+" in raw and ("'" in raw or '"' in raw)) or bool(re.search(r'\{[a-zA-Z_][a-zA-Z0-9_]*\}', raw)) or ("%s" in raw)

        # Extract literal predicates in WHERE / SET clauses
        where_match = cls.COLUMN_PATTERNS[3].search(raw)
        literal_predicates = []
        if where_match:
            for col, op, full_val, str_s, str_d, num in cls.LITERAL_PREDICATE_REGEX.findall(where_match.group(1)):
                literal_predicates.append({
                    "column": col.strip().split(".")[-1],
                    "operator": op,
                    "value": str_s if str_s else (str_d if str_d else num),
                    "is_string": bool(str_s or str_d),
                })

        # Validate syntax
        is_valid, syntax_err = cls.validate_sqlite_syntax(raw, tables, columns)

        is_ddl = stmt_type in (
            SQLiteStatementType.CREATE_TABLE,
            SQLiteStatementType.ALTER_TABLE,
            SQLiteStatementType.DROP_TABLE,
            SQLiteStatementType.CREATE_INDEX,
            SQLiteStatementType.DROP_INDEX,
            SQLiteStatementType.CREATE_VIEW,
            SQLiteStatementType.DROP_VIEW,
            SQLiteStatementType.CREATE_TRIGGER,
            SQLiteStatementType.DROP_TRIGGER,
            SQLiteStatementType.PRAGMA,
            SQLiteStatementType.TRANSACTION,
        )

        can_verify = is_valid and not is_ddl
        limitation = None
        if not is_valid:
            limitation = f"SQLite syntax error: {syntax_err}"
        elif is_ddl:
            limitation = f"Statement type '{stmt_type.value}' is a DDL/administrative operation. Dynamic SQL injection verification requires executable query operations (SELECT/INSERT/UPDATE/DELETE)."

        # Determine target parameters
        parameters: list[str] = []
        if literal_predicates:
            parameters = [p["column"] for p in literal_predicates]
        elif columns:
            parameters = columns[:2]
        else:
            parameters = ["id"]

        return ParsedSQLiteQuery(
            raw_query=raw,
            statement_type=stmt_type,
            is_valid_syntax=is_valid,
            syntax_error=syntax_err,
            tables=tables if tables else ["records"],
            columns=columns if columns else ["id", "data"],
            parameters=parameters,
            parameter_markers=param_markers,
            literal_predicates=literal_predicates,
            is_parameterized=is_parameterized,
            has_dynamic_construction=has_dynamic,
            is_ddl_or_pragma=is_ddl,
            can_dynamically_verify=can_verify,
            verification_limitation=limitation,
        )

    @classmethod
    def synthesize_mock_db(
        cls,
        connection: sqlite3.Connection,
        tables: list[str],
        columns: list[str],
    ) -> None:
        """
        Dynamically create and seed discovered tables in an isolated in-memory SQLite connection.
        Ensures both custom discovered schemas and the default users schema exist,
        allowing arbitrary queries and legacy scenario tests to execute safely.
        """
        cursor = connection.cursor()

        # 1. Always ensure default users table exists for backward compatibility
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

        # 2. Provision each discovered custom table
        for table in tables:
            if table.lower() == "users":
                continue
            cursor.execute(f"DROP TABLE IF EXISTS {table}")
            col_defs = ["id INTEGER PRIMARY KEY AUTOINCREMENT"]
            col_names = []
            for col in columns:
                if col.lower() != "id":
                    col_defs.append(f"{col} TEXT")
                    col_names.append(col)

            # Ensure at least two identifiable string columns if none found
            if not col_names:
                col_defs.extend(["name TEXT", "status TEXT", "category TEXT", "total REAL"])
                col_names = ["name", "status", "category", "total"]

            create_sql = f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(col_defs)})"
            cursor.execute(create_sql)

            # Seed 3 rows of synthetic data matching the columns
            placeholders = ", ".join(["?"] * len(col_names))
            insert_sql = f"INSERT INTO {table} ({', '.join(col_names)}) VALUES ({placeholders})"

            seed_rows = [
                tuple(
                    "alice" if "user" in c.lower() or "name" in c.lower()
                    else ("active" if "status" in c.lower()
                    else ("electronics" if "cat" in c.lower()
                    else ("admin@example.local" if "email" in c.lower() else "100.00")))
                    for c in col_names
                ),
                tuple(
                    "bob" if "user" in c.lower() or "name" in c.lower()
                    else ("pending" if "status" in c.lower()
                    else ("books" if "cat" in c.lower()
                    else ("user@example.local" if "email" in c.lower() else "50.00")))
                    for c in col_names
                ),
                tuple(
                    "charlie" if "user" in c.lower() or "name" in c.lower()
                    else ("closed" if "status" in c.lower()
                    else ("home" if "cat" in c.lower()
                    else ("charlie@example.local" if "email" in c.lower() else "25.00")))
                    for c in col_names
                ),
            ]
            cursor.executemany(insert_sql, seed_rows)

        connection.commit()
