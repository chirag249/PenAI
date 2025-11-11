DEFAULTS = {
    "concurrency": 10,
    "timeout": 8,
    "user_agent": "PenAI-Min/1.0 (+safe-mode)",
    "sql_error_signatures": [
        "SQL syntax",
        "mysql_fetch",
        "ORA-01756",
        "syntax error at or near",
        "SQLSTATE"
    ],
    "xss_reflection_markers": ["<script>alert(1)</script>", "alert(1)"]
}
