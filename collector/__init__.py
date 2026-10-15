"""AgentGuard Collector — modular package."""

# ✅ Backward compatibility exports
from collector.app import create_app
from collector.db import (
    get_db,
    init_db,
    is_postgres,
    redact_pii,
    sql_false,
    sql_placeholder,
    sql_true,
)

__all__ = [
    "create_app",
    "get_db",
    "init_db",
    "is_postgres",
    "redact_pii",
    "sql_false",
    "sql_placeholder",
    "sql_true",
]
