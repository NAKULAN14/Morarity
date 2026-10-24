"""
Structured SQL Injection Test Catalog for Moriarty Adaptive Security Verification.

Organized by:
- Test Category (12 standard security testing categories)
- Database Dialect (SQLite initially, expandable to PostgreSQL/MySQL)
- Query Context (WHERE equality, numeric filter, UNION boundary, etc.)
- Input Type (String, Numeric, Hex-encoded, Special characters, Benign name)
- Security Invariant (Exact security invariant challenged)
- Expected Behavior (Differential security expectations)
- Test Execution Support (SUPPORTED in SQLite vs UNSUPPORTED_IN_DRIVER_API)
- Verification Status
"""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Optional


class SQLInjectionCategory(str, Enum):
    QUOTE_DELIMITER = "Quote and delimiter handling"
    BOOLEAN_BASED = "Boolean-based SQL injection"
    COMMENT_DELIMITER = "Comment-based SQL injection"
    UNION_BASED = "UNION-based SQL injection"
    STACKED_QUERIES = "Stacked statement handling"
    NUMERIC_CONTEXT = "Numeric parameter handling"
    LIKE_PATTERN = "LIKE-pattern behavior"
    TYPE_CONFUSION = "Type confusion"
    ENCODING_NORMALIZATION = "Input encoding and normalization"
    AUTHENTICATION_BYPASS = "Authentication query behavior"
    DATABASE_ERROR = "Database error handling"
    BENIGN_FUNCTIONALITY = "Legitimate functionality preservation"


@dataclass
class SQLInjectionTestCase:
    test_id: str
    name: str
    category: str
    dialect: str
    query_context: str
    input_type: str
    security_invariant: str
    payload: str
    expected_behavior: str
    execution_support: str = "SUPPORTED"  # "SUPPORTED" | "UNSUPPORTED_IN_DRIVER_API"
    verification_weight: str = "HIGH"    # "CRITICAL" | "HIGH" | "MEDIUM"
    is_benign: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# =============================================================================
# The Comprehensive SQL Injection Test Catalog
# =============================================================================

SQL_INJECTION_CATALOG: list[SQLInjectionTestCase] = [
    # -------------------------------------------------------------------------
    # 1. Quote and delimiter handling
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_QUOTE_001",
        name="Single Quote String Termination Tautology",
        category=SQLInjectionCategory.QUOTE_DELIMITER.value,
        dialect="SQLite",
        query_context="WHERE_STRING_LITERAL",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ESCAPE_STRING_DELIMITER",
        payload="' OR '1'='1",
        expected_behavior="Patched target binds input strictly as data; returns 0 unauthorized rows.",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        description="Verifies that single quote characters in input cannot terminate the string literal in the query.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_QUOTE_002",
        name="Empty String Delimiter Boundary Probe",
        category=SQLInjectionCategory.QUOTE_DELIMITER.value,
        dialect="SQLite",
        query_context="WHERE_STRING_LITERAL",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ESCAPE_STRING_DELIMITER",
        payload="'' OR ''='",
        expected_behavior="Treated as literal empty quotes string; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests whether adjacent quote marks trigger unescaped delimiter expansion.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_QUOTE_003",
        name="Single Quote with Empty String Equality",
        category=SQLInjectionCategory.QUOTE_DELIMITER.value,
        dialect="SQLite",
        query_context="WHERE_STRING_LITERAL",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ESCAPE_STRING_DELIMITER",
        payload="' OR ''='",
        expected_behavior="Literal string comparison without SQL grammar manipulation; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Challenges boundary delimiter handling with an empty string comparison operand.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_QUOTE_004",
        name="Targeted Identity with Escaped Quote Boundary",
        category=SQLInjectionCategory.QUOTE_DELIMITER.value,
        dialect="SQLite",
        query_context="WHERE_STRING_LITERAL",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ESCAPE_STRING_DELIMITER",
        payload="admin'' OR '1'='1",
        expected_behavior="Targeted prefix with escaped single quote treated as literal username; returns 0 rows.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Ensures quotes embedded within token text cannot breakout and force tautology.",
    ),

    # -------------------------------------------------------------------------
    # 2. Boolean-based SQL injection
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_BOOL_001",
        name="Standard Numeric Boolean Tautology with Comment",
        category=SQLInjectionCategory.BOOLEAN_BASED.value,
        dialect="SQLite",
        query_context="WHERE_PREDICATE",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_FORCE_BOOLEAN_TAUTOLOGY",
        payload="' OR 1=1 --",
        expected_behavior="Treated as literal parameter; evaluates to false for existing usernames; returns 0 rows.",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        description="Verifies that numeric equality tautologies cannot force query predicate to true.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_BOOL_002",
        name="Relational Inequality Boolean Tautology",
        category=SQLInjectionCategory.BOOLEAN_BASED.value,
        dialect="SQLite",
        query_context="WHERE_PREDICATE",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_FORCE_BOOLEAN_TAUTOLOGY",
        payload="' OR 2>1 --",
        expected_behavior="Relational operator handled as plain string; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests whether inequality operators (> / <) can be injected into WHERE clause.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_BOOL_003",
        name="Character Literal Boolean Tautology",
        category=SQLInjectionCategory.BOOLEAN_BASED.value,
        dialect="SQLite",
        query_context="WHERE_PREDICATE",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_FORCE_BOOLEAN_TAUTOLOGY",
        payload="' OR 'a'='a",
        expected_behavior="Character comparison treated as string data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Evaluates string comparison tautology without trailing comment symbols.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_BOOL_004",
        name="Compound Parenthesized Boolean Expression",
        category=SQLInjectionCategory.BOOLEAN_BASED.value,
        dialect="SQLite",
        query_context="WHERE_PREDICATE",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_FORCE_BOOLEAN_TAUTOLOGY",
        payload="' OR (1=1 AND 2=2) --",
        expected_behavior="Parentheses and logical AND operator treated as literal string; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Checks whether nested parentheses in boolean clauses alter query precedence.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_BOOL_005",
        name="Negated Condition Boolean Tautology",
        category=SQLInjectionCategory.BOOLEAN_BASED.value,
        dialect="SQLite",
        query_context="WHERE_PREDICATE",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_FORCE_BOOLEAN_TAUTOLOGY",
        payload="' OR NOT (1=2) --",
        expected_behavior="NOT keyword handled as literal data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="MEDIUM",
        description="Tests injection of NOT negation operators to alter logic truth tables.",
    ),

    # -------------------------------------------------------------------------
    # 3. Comment-based SQL injection
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_COMM_001",
        name="SQL Line Comment Delimiter Truncation",
        category=SQLInjectionCategory.COMMENT_DELIMITER.value,
        dialect="SQLite",
        query_context="WHERE_CLAUSE_TAIL",
        input_type="STRING",
        security_invariant="SQL_COMMENT_MARKERS_CANNOT_TRUNCATE_QUERY",
        payload="' OR 1=1 --",
        expected_behavior="Double dash treated as literal text; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        description="Verifies that standard SQL line comment '--' cannot truncate query syntax.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_COMM_002",
        name="C-Style Block Comment Truncation",
        category=SQLInjectionCategory.COMMENT_DELIMITER.value,
        dialect="SQLite",
        query_context="WHERE_CLAUSE_TAIL",
        input_type="STRING",
        security_invariant="SQL_COMMENT_MARKERS_CANNOT_TRUNCATE_QUERY",
        payload="' OR 1=1 /*",
        expected_behavior="Slash-asterisk block comment treated as data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Verifies that C-style block comments '/*' cannot swallow subsequent query statements.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_COMM_003",
        name="Targeted Identity Comment Truncation",
        category=SQLInjectionCategory.COMMENT_DELIMITER.value,
        dialect="SQLite",
        query_context="WHERE_CLAUSE_TAIL",
        input_type="STRING",
        security_invariant="SQL_COMMENT_MARKERS_CANNOT_TRUNCATE_QUERY",
        payload="admin' --",
        expected_behavior="Returns 0 records (unless username is literally \"admin' --\").",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        description="Tests whether comments can truncate secondary password or tenant isolation checks.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_COMM_004",
        name="Comment Following Semicolon Delimiter",
        category=SQLInjectionCategory.COMMENT_DELIMITER.value,
        dialect="SQLite",
        query_context="WHERE_CLAUSE_TAIL",
        input_type="STRING",
        security_invariant="SQL_COMMENT_MARKERS_CANNOT_TRUNCATE_QUERY",
        payload="' OR 1=1; --",
        expected_behavior="Semicolon and dash treated as text parameter; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="MEDIUM",
        description="Checks semicolon termination combined with line comments.",
    ),

    # -------------------------------------------------------------------------
    # 4. UNION-based SQL injection
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_UNION_001",
        name="UNION Synthetic Identity Data Injection",
        category=SQLInjectionCategory.UNION_BASED.value,
        dialect="SQLite",
        query_context="UNION_QUERY_EXTENSION",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_INJECT_UNION_DATA",
        payload="' UNION SELECT 99, 'injected_user', 'admin', 'injected@moriarty.local' --",
        expected_behavior="UNION keyword treated as literal data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        description="Verifies that UNION SELECT cannot append unauthorized synthetic record rows to result sets.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_UNION_002",
        name="UNION Query with Filter Sub-Condition",
        category=SQLInjectionCategory.UNION_BASED.value,
        dialect="SQLite",
        query_context="UNION_QUERY_EXTENSION",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_INJECT_UNION_DATA",
        payload="' UNION SELECT 100, 'audit_probe', 'analyst', 'audit@sec.local' WHERE '1'='1' --",
        expected_behavior="Full UNION statement bound as parameter; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests complex UNION queries containing secondary internal WHERE clauses.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_UNION_003",
        name="UNION Self-Selection Cross-Query",
        category=SQLInjectionCategory.UNION_BASED.value,
        dialect="SQLite",
        query_context="UNION_QUERY_EXTENSION",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_INJECT_UNION_DATA",
        payload="' UNION SELECT id, username, role, email FROM users --",
        expected_behavior="Treated as literal query string; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests reflection of entire table data via UNION self-selection.",
    ),

    # -------------------------------------------------------------------------
    # 5. Stacked statement handling (Unsupported in SQLite cursor.execute API)
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_STACK_001",
        name="Stacked Semicolon Secondary SELECT Statement",
        category=SQLInjectionCategory.STACKED_QUERIES.value,
        dialect="SQLite",
        query_context="STATEMENT_CHAIN",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_EXECUTE_STACKED_STATEMENTS",
        payload="'; SELECT 1; --",
        expected_behavior="Driver restricts multi-statement execution in cursor.execute; classified as unsupported in driver API.",
        execution_support="UNSUPPORTED_IN_DRIVER_API",
        verification_weight="HIGH",
        description="SQLite cursor.execute explicitly disallows stacked queries. Cataloged for completeness but marked unsupported in driver API.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_STACK_002",
        name="Stacked Semicolon Data Modification INSERT",
        category=SQLInjectionCategory.STACKED_QUERIES.value,
        dialect="SQLite",
        query_context="STATEMENT_CHAIN",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_EXECUTE_STACKED_STATEMENTS",
        payload="'; INSERT INTO users VALUES (99, 'evil', 'admin', 'evil@evil.com'); --",
        expected_behavior="Driver restricts multi-statement execution in cursor.execute; not executed against SQLite.",
        execution_support="UNSUPPORTED_IN_DRIVER_API",
        verification_weight="HIGH",
        description="Multi-statement data modification probe. Documented as unsupported in SQLite execute driver API.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_STACK_003",
        name="Stacked Semicolon Destructive DDL DROP TABLE",
        category=SQLInjectionCategory.STACKED_QUERIES.value,
        dialect="SQLite",
        query_context="STATEMENT_CHAIN",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_EXECUTE_STACKED_STATEMENTS",
        payload="'; DROP TABLE users; --",
        expected_behavior="Driver restricts multi-statement execution in cursor.execute; not executed against SQLite.",
        execution_support="UNSUPPORTED_IN_DRIVER_API",
        verification_weight="CRITICAL",
        description="Destructive DDL stacked statement probe. Documented as unsupported in SQLite execute driver API.",
    ),

    # -------------------------------------------------------------------------
    # 6. Numeric parameter handling
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_NUM_001",
        name="Truthy Numeric Constant Literal Injection",
        category=SQLInjectionCategory.NUMERIC_CONTEXT.value,
        dialect="SQLite",
        query_context="NUMERIC_EVALUATION",
        input_type="NUMERIC",
        security_invariant="NUMERIC_OPERATORS_CANNOT_EVALUATE_IN_INPUT",
        payload="' OR 1 --",
        expected_behavior="Treated as literal string \"' OR 1 --\"; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Verifies that truthy numeric values (1) do not coerce SQL WHERE evaluation.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_NUM_002",
        name="Arithmetic Addition Expression Evaluation",
        category=SQLInjectionCategory.NUMERIC_CONTEXT.value,
        dialect="SQLite",
        query_context="NUMERIC_EVALUATION",
        input_type="NUMERIC",
        security_invariant="NUMERIC_OPERATORS_CANNOT_EVALUATE_IN_INPUT",
        payload="' OR 0+1=1 --",
        expected_behavior="Arithmetic addition operator (+) treated as literal text; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Ensures arithmetic operations are not dynamically evaluated by the query compiler.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_NUM_003",
        name="Arithmetic Subtraction Expression Evaluation",
        category=SQLInjectionCategory.NUMERIC_CONTEXT.value,
        dialect="SQLite",
        query_context="NUMERIC_EVALUATION",
        input_type="NUMERIC",
        security_invariant="NUMERIC_OPERATORS_CANNOT_EVALUATE_IN_INPUT",
        payload="' OR 10-5=5 --",
        expected_behavior="Arithmetic subtraction operator (-) treated as literal text; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="MEDIUM",
        description="Ensures subtraction operations are not dynamically evaluated.",
    ),

    # -------------------------------------------------------------------------
    # 7. LIKE-pattern behavior
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_LIKE_001",
        name="SQL LIKE Wildcard All Tautology",
        category=SQLInjectionCategory.LIKE_PATTERN.value,
        dialect="SQLite",
        query_context="LIKE_PATTERN_MATCH",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_PREDICATE_LOGIC",
        payload="' OR username LIKE '%' --",
        expected_behavior="LIKE wildcard syntax bound as literal data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests whether SQL LIKE wildcard '%' can be injected to match all records.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_LIKE_002",
        name="SQL LIKE Single Character Prefix Wildcard",
        category=SQLInjectionCategory.LIKE_PATTERN.value,
        dialect="SQLite",
        query_context="LIKE_PATTERN_MATCH",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_PREDICATE_LOGIC",
        payload="' OR username LIKE 'a%' --",
        expected_behavior="Prefix wildcard treated as data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests whether partial character wildcards can leak specific record sets.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_LIKE_003",
        name="Literal LIKE String Comparison",
        category=SQLInjectionCategory.LIKE_PATTERN.value,
        dialect="SQLite",
        query_context="LIKE_PATTERN_MATCH",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_PREDICATE_LOGIC",
        payload="' OR '1' LIKE '1",
        expected_behavior="LIKE operator inside injected string treated as data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="MEDIUM",
        description="Evaluates inline LIKE evaluation without trailing comment delimiters.",
    ),

    # -------------------------------------------------------------------------
    # 8. Type confusion
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_TYPE_001",
        name="SQLite typeof() Type Introspection Injection",
        category=SQLInjectionCategory.TYPE_CONFUSION.value,
        dialect="SQLite",
        query_context="TYPE_INTROSPECTION",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_QUERY_SYNTAX",
        payload="' OR typeof(username)='text' --",
        expected_behavior="typeof function treated as text parameter; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests whether database type introspection functions can be injected into WHERE predicates.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_TYPE_002",
        name="Scalar Subquery Integer Comparison",
        category=SQLInjectionCategory.TYPE_CONFUSION.value,
        dialect="SQLite",
        query_context="TYPE_INTROSPECTION",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_QUERY_SYNTAX",
        payload="' OR (SELECT 1)=1 --",
        expected_behavior="Subquery parentheses treated as parameter; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests whether nested scalar subqueries can coerce type evaluation.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_TYPE_003",
        name="Function-Based Predicate Evaluation length()",
        category=SQLInjectionCategory.TYPE_CONFUSION.value,
        dialect="SQLite",
        query_context="TYPE_INTROSPECTION",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_QUERY_SYNTAX",
        payload="' OR length(username)>0 --",
        expected_behavior="Length function treated as plain data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="MEDIUM",
        description="Tests whether length functions can dynamically inspect database content.",
    ),

    # -------------------------------------------------------------------------
    # 9. Input encoding and normalization
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_ENC_001",
        name="char() Function Dynamic Character Synthesis",
        category=SQLInjectionCategory.ENCODING_NORMALIZATION.value,
        dialect="SQLite",
        query_context="ENCODING_BYPASS",
        input_type="SPECIAL_CHARS",
        security_invariant="SPECIAL_CHARACTERS_TREATED_STRICTLY_AS_LITERAL_DATA",
        payload="' OR char(49)=char(49) --",
        expected_behavior="char() invocation treated as literal string; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests evasion attempts that construct SQL characters dynamically using char(ASCII).",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_ENC_002",
        name="Hex Blob Literal Comparison Injection",
        category=SQLInjectionCategory.ENCODING_NORMALIZATION.value,
        dialect="SQLite",
        query_context="ENCODING_BYPASS",
        input_type="HEX_ENCODED",
        security_invariant="SPECIAL_CHARACTERS_TREATED_STRICTLY_AS_LITERAL_DATA",
        payload="' OR x'61'=x'61' --",
        expected_behavior="x'..' blob literal treated as literal text; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests hexadecimal blob literal evasion (x'61' == 'a').",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_ENC_003",
        name="hex() Function Encoding Comparison",
        category=SQLInjectionCategory.ENCODING_NORMALIZATION.value,
        dialect="SQLite",
        query_context="ENCODING_BYPASS",
        input_type="HEX_ENCODED",
        security_invariant="SPECIAL_CHARACTERS_TREATED_STRICTLY_AS_LITERAL_DATA",
        payload="' OR hex('a')=hex('a') --",
        expected_behavior="hex() function treated as text; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="MEDIUM",
        description="Tests hex encoding function comparisons inside query parameters.",
    ),

    # -------------------------------------------------------------------------
    # 10. Authentication query behavior
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_AUTH_001",
        name="Targeted Administrator Account Bypass",
        category=SQLInjectionCategory.AUTHENTICATION_BYPASS.value,
        dialect="SQLite",
        query_context="AUTH_PREDICATE",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_AUTHENTICATION_IDENTITY",
        payload="admin' --",
        expected_behavior="Searches for exact username \"admin' --\"; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        description="Verifies that admin account lookup cannot be forced via trailing comments.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_AUTH_002",
        name="Privilege Escalation Role Predicate Injection",
        category=SQLInjectionCategory.AUTHENTICATION_BYPASS.value,
        dialect="SQLite",
        query_context="AUTH_PREDICATE",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_AUTHENTICATION_IDENTITY",
        payload="' OR role='admin' --",
        expected_behavior="Treated as literal data; returns 0 records (does not return admin user).",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        description="Tests injection of secondary column filters targeting administrative roles.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_AUTH_003",
        name="Targeted Identity Tautology Combination",
        category=SQLInjectionCategory.AUTHENTICATION_BYPASS.value,
        dialect="SQLite",
        query_context="AUTH_PREDICATE",
        input_type="STRING",
        security_invariant="UNTRUSTED_INPUT_CANNOT_ALTER_AUTHENTICATION_IDENTITY",
        payload="charlie' OR '1'='1",
        expected_behavior="Treated as literal text; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests targeted identity prefix combined with boolean tautology without comment delimiters.",
    ),

    # -------------------------------------------------------------------------
    # 11. Database error handling
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="SQLI_ERR_001",
        name="Type Cast Function CAST() Probe",
        category=SQLInjectionCategory.DATABASE_ERROR.value,
        dialect="SQLite",
        query_context="ERROR_HANDLING",
        input_type="STRING",
        security_invariant="ERROR_FREE_EXECUTION_FOR_SPECIAL_DELIMITERS",
        payload="' OR 1=CAST('1' AS INTEGER) --",
        expected_behavior="Executes safely without runtime error or schema leakage; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Tests CAST function evaluation to ensure type conversion handles input safely.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_ERR_002",
        name="Conditional CASE-WHEN-THEN Expression Probe",
        category=SQLInjectionCategory.DATABASE_ERROR.value,
        dialect="SQLite",
        query_context="ERROR_HANDLING",
        input_type="STRING",
        security_invariant="ERROR_FREE_EXECUTION_FOR_SPECIAL_DELIMITERS",
        payload="' OR CASE WHEN 1=1 THEN 1 ELSE 0 END=1 --",
        expected_behavior="CASE expression treated as parameter text; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        description="Verifies that conditional CASE expressions are not dynamically evaluated.",
    ),
    SQLInjectionTestCase(
        test_id="SQLI_ERR_003",
        name="Null-Handling nullif() Function Probe",
        category=SQLInjectionCategory.DATABASE_ERROR.value,
        dialect="SQLite",
        query_context="ERROR_HANDLING",
        input_type="STRING",
        security_invariant="ERROR_FREE_EXECUTION_FOR_SPECIAL_DELIMITERS",
        payload="' OR nullif(1, 0)=1 --",
        expected_behavior="Null-handling functions handled as parameter data; returns 0 records.",
        execution_support="SUPPORTED",
        verification_weight="MEDIUM",
        description="Ensures null-coalescing functions do not cause unexpected query execution.",
    ),

    # -------------------------------------------------------------------------
    # 12. Legitimate functionality preservation
    # -------------------------------------------------------------------------
    SQLInjectionTestCase(
        test_id="FUNC_BENIGN_001",
        name="Legitimate User Lookup: Alice",
        category=SQLInjectionCategory.BENIGN_FUNCTIONALITY.value,
        dialect="SQLite",
        query_context="BENIGN_LOOKUP",
        input_type="BENIGN_NAME",
        security_invariant="BENIGN_USER_LOOKUP_PRESERVED",
        payload="alice",
        expected_behavior="Returns exactly 1 record matching username 'alice'.",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        is_benign=True,
        description="Ensures legitimate application user query functionality remains intact for 'alice'.",
    ),
    SQLInjectionTestCase(
        test_id="FUNC_BENIGN_002",
        name="Legitimate User Lookup: Bob",
        category=SQLInjectionCategory.BENIGN_FUNCTIONALITY.value,
        dialect="SQLite",
        query_context="BENIGN_LOOKUP",
        input_type="BENIGN_NAME",
        security_invariant="BENIGN_USER_LOOKUP_PRESERVED",
        payload="bob",
        expected_behavior="Returns exactly 1 record matching username 'bob'.",
        execution_support="SUPPORTED",
        verification_weight="CRITICAL",
        is_benign=True,
        description="Ensures legitimate application user query functionality remains intact for 'bob'.",
    ),
    SQLInjectionTestCase(
        test_id="FUNC_BENIGN_003",
        name="Legitimate User Lookup: Charlie (Admin)",
        category=SQLInjectionCategory.BENIGN_FUNCTIONALITY.value,
        dialect="SQLite",
        query_context="BENIGN_LOOKUP",
        input_type="BENIGN_NAME",
        security_invariant="BENIGN_USER_LOOKUP_PRESERVED",
        payload="charlie",
        expected_behavior="Returns exactly 1 record matching username 'charlie'.",
        execution_support="SUPPORTED",
        verification_weight="HIGH",
        is_benign=True,
        description="Ensures administrative record lookup remains operational for authentic admin 'charlie'.",
    ),
]


# =============================================================================
# Catalog Accessors and Utility Functions
# =============================================================================

def get_catalog() -> list[SQLInjectionTestCase]:
    """Return the complete test catalog."""
    return list(SQL_INJECTION_CATALOG)


def get_categories() -> list[dict[str, Any]]:
    """Return summary metadata for all 12 test categories."""
    categories_meta = []
    for cat in SQLInjectionCategory:
        tests = [t for t in SQL_INJECTION_CATALOG if t.category == cat.value]
        supported = [t for t in tests if t.execution_support == "SUPPORTED"]
        unsupported = [t for t in tests if t.execution_support != "SUPPORTED"]
        categories_meta.append({
            "name": cat.value,
            "total_tests": len(tests),
            "supported_tests": len(supported),
            "unsupported_tests": len(unsupported),
            "is_executable_in_sqlite": len(supported) > 0,
        })
    return categories_meta


def get_executable_tests() -> list[SQLInjectionTestCase]:
    """Return only tests supported for direct dynamic execution in SQLite."""
    return [t for t in SQL_INJECTION_CATALOG if t.execution_support == "SUPPORTED"]


def get_tests_by_category(category: str) -> list[SQLInjectionTestCase]:
    """Filter catalog by category name."""
    return [t for t in SQL_INJECTION_CATALOG if t.category.lower() == category.lower()]


def get_test_by_id(test_id: str) -> Optional[SQLInjectionTestCase]:
    """Lookup specific test case by ID."""
    for t in SQL_INJECTION_CATALOG:
        if t.test_id == test_id:
            return t
    return None
