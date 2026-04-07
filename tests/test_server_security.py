import pytest

from mssql_mcp_server.server import SecurityConfig
from mssql_mcp_server.server import validate_read_only_sql
from mssql_mcp_server.server import validate_resource_access


ALLOWED_SCHEMAS = frozenset({"dbo"})


@pytest.mark.parametrize(
    "query",
    [
        "SELECT TOP 10 * FROM dbo.Clientes",
        "WITH cte AS (SELECT TOP 5 * FROM dbo.Clientes) SELECT * FROM cte",
        "SELECT COUNT(*) FROM dbo.Ordenes",
    ],
)
def test_validate_read_only_sql_allows_safe_queries(query):
    ok, reason = validate_read_only_sql(query, ALLOWED_SCHEMAS)
    assert ok is True
    assert reason is None


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("DELETE FROM dbo.Clientes", "only SELECT and WITH"),
        ("UPDATE dbo.Clientes SET nombre='x'", "only SELECT and WITH"),
        ("INSERT INTO dbo.Clientes VALUES (1)", "only SELECT and WITH"),
        ("SELECT * INTO dbo.tmp FROM dbo.Clientes", "blocked token detected: INTO"),
        ("EXEC sp_helpdb", "only SELECT and WITH"),
        ("DROP TABLE dbo.Clientes", "only SELECT and WITH"),
        (
            "SELECT * FROM dbo.Clientes; DELETE FROM dbo.Clientes",
            "multiple statements are not allowed",
        ),
        ("SELECT 1\nGO\nSELECT 2", "GO batch separators are not allowed"),
        ("SELECT * FROM other.Clientes", "schema not allowed: other"),
    ],
)
def test_validate_read_only_sql_blocks_dangerous_queries(query, expected):
    ok, reason = validate_read_only_sql(query, ALLOWED_SCHEMAS)
    assert ok is False
    assert expected in reason


def test_validate_read_only_sql_respects_allowed_tables():
    ok, reason = validate_read_only_sql(
        "SELECT * FROM dbo.Secretos",
        ALLOWED_SCHEMAS,
        allowed_tables=frozenset({"dbo.clientes", "dbo.ordenes"}),
    )

    assert ok is False
    assert reason == "table not allowed: dbo.secretos"


def test_validate_read_only_sql_metadata_only_blocks_user_tables():
    ok, reason = validate_read_only_sql(
        "SELECT * FROM dbo.Clientes",
        ALLOWED_SCHEMAS,
        allow_metadata_only=True,
    )

    assert ok is False
    assert reason == "metadata-only mode blocks user-table reads"


def test_validate_resource_access_blocks_data_and_non_allowlisted_tables():
    security = SecurityConfig(
        read_only=True,
        max_rows=200,
        max_tables=100,
        query_timeout=30,
        allowed_schemas=frozenset({"dbo"}),
        allowed_tables=frozenset({"dbo.clientes"}),
        block_schema_samples=True,
        block_data_resources=True,
        allow_metadata_only=False,
        max_query_length=20000,
    )

    ok, reason = validate_resource_access("dbo", "Clientes", "schema", security)
    assert ok is True
    assert reason is None

    ok, reason = validate_resource_access("dbo", "Clientes", "data", security)
    assert ok is False
    assert reason == "data resources are disabled"

    ok, reason = validate_resource_access("dbo", "Secretos", "schema", security)
    assert ok is False
    assert reason == "resource not allowed: dbo.Secretos"
