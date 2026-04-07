#!/usr/bin/env python3
"""
MSSQL MCP Server - A Model Context Protocol server for Microsoft SQL Server.
Provides read-only SQL query execution and table introspection capabilities via MCP.
"""

import asyncio
import hashlib
import logging
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

import sqlparse
from mcp.server import Server
from mcp.types import Resource, TextContent, Tool
from pydantic import AnyUrl
from pyodbc import Error as PyODBCError
from pyodbc import connect
from sqlparse import sql
from sqlparse import tokens as T


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("mssql_mcp_server")

__version__ = "1.0.0"
__author__ = "MSSQL MCP Server Contributors"

DEFAULT_MAX_QUERY_LENGTH = 20_000
METADATA_SCHEMAS = frozenset({"information_schema", "sys"})
READ_ONLY_BLOCKED_TOKENS = frozenset(
    {
        "INSERT",
        "UPDATE",
        "DELETE",
        "MERGE",
        "ALTER",
        "DROP",
        "TRUNCATE",
        "CREATE",
        "EXEC",
        "EXECUTE",
        "GRANT",
        "REVOKE",
        "DENY",
        "BACKUP",
        "RESTORE",
        "DBCC",
        "USE",
        "DECLARE",
        "SET",
        "INTO",
        "BULK",
        "OPENROWSET",
        "OPENDATASOURCE",
        "WAITFOR",
    }
)
FROM_LIKE_KEYWORDS = {
    "FROM",
    "JOIN",
    "INNER JOIN",
    "LEFT JOIN",
    "RIGHT JOIN",
    "FULL JOIN",
    "CROSS JOIN",
    "LEFT OUTER JOIN",
    "RIGHT OUTER JOIN",
    "FULL OUTER JOIN",
    "CROSS APPLY",
    "OUTER APPLY",
}


@dataclass(frozen=True)
class SecurityConfig:
    read_only: bool
    max_rows: int
    max_tables: int
    query_timeout: int
    allowed_schemas: FrozenSet[str]
    allowed_tables: FrozenSet[str]
    block_schema_samples: bool
    block_data_resources: bool
    allow_metadata_only: bool
    max_query_length: int


def _parse_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_csv_set(value: Optional[str]) -> FrozenSet[str]:
    if not value:
        return frozenset()
    return frozenset(item.strip().lower() for item in value.split(",") if item.strip())


@lru_cache(maxsize=1)
def load_security_config() -> SecurityConfig:
    allowed_schemas = _parse_csv_set(os.getenv("MSSQL_ALLOWED_SCHEMAS", "dbo"))
    max_rows = max(1, int(os.getenv("MSSQL_MAX_ROWS", "200")))
    max_tables = max(1, int(os.getenv("MSSQL_MAX_TABLES", "100")))
    query_timeout = max(1, int(os.getenv("MSSQL_QUERY_TIMEOUT", "30")))
    max_query_length = max(
        256, int(os.getenv("MSSQL_MAX_QUERY_LENGTH", str(DEFAULT_MAX_QUERY_LENGTH)))
    )

    config = SecurityConfig(
        read_only=_parse_bool("MSSQL_READ_ONLY", True),
        max_rows=max_rows,
        max_tables=max_tables,
        query_timeout=query_timeout,
        allowed_schemas=allowed_schemas or frozenset({"dbo"}),
        allowed_tables=_parse_csv_set(os.getenv("MSSQL_ALLOWED_TABLES")),
        block_schema_samples=_parse_bool("MSSQL_BLOCK_SCHEMA_SAMPLES", True),
        block_data_resources=_parse_bool("MSSQL_BLOCK_DATA_RESOURCES", True),
        allow_metadata_only=_parse_bool("MSSQL_ALLOW_METADATA_ONLY", False),
        max_query_length=max_query_length,
    )

    logger.info(
        "Security config loaded | read_only=%s max_rows=%s max_tables=%s timeout=%ss schemas=%s tables=%s metadata_only=%s data_resources=%s",
        config.read_only,
        config.max_rows,
        config.max_tables,
        config.query_timeout,
        ",".join(sorted(config.allowed_schemas)),
        len(config.allowed_tables),
        config.allow_metadata_only,
        not config.block_data_resources,
    )
    return config


def normalize_identifier(value: str) -> str:
    cleaned = value.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    if cleaned.startswith('"') and cleaned.endswith('"'):
        cleaned = cleaned[1:-1]
    return cleaned.strip().lower()


def normalize_table_name(schema: str, table: str) -> str:
    return f"{normalize_identifier(schema)}.{normalize_identifier(table)}"


def escape_odbc_value(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"


def build_query_fingerprint(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8", errors="ignore")).hexdigest()[:12]


def strip_sql_comments(query: str) -> str:
    if not query:
        return query

    result: List[str] = []
    i = 0
    in_string = False
    in_line_comment = False
    in_block_comment = False

    while i < len(query):
        pair = query[i : i + 2]
        char = query[i]

        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                result.append(char)
            i += 1
            continue

        if in_block_comment:
            if pair == "*/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        if not in_string and pair == "--":
            in_line_comment = True
            i += 2
            continue

        if not in_string and pair == "/*":
            in_block_comment = True
            i += 2
            continue

        if char == "'":
            if in_string and i + 1 < len(query) and query[i + 1] == "'":
                result.append("''")
                i += 2
                continue
            in_string = not in_string

        result.append(char)
        i += 1

    return "".join(result)


class QueryPreprocessor:
    """Handles preprocessing of SQL queries."""

    @staticmethod
    def preprocess_query(query: str) -> str:
        if not query:
            return query

        query = query.replace("\x00", "").strip()
        query = query.replace("\r", "")
        query = re.sub(r"[\t\f\v]+", " ", query)
        query = re.sub(r"\n+", "\n", query)
        query = re.sub(r"[ ]{2,}", " ", query)
        return query.strip()


class DatabaseConfig:
    """Handles database configuration from environment variables."""

    @staticmethod
    def get_config() -> Tuple[Dict[str, Any], str]:
        server = os.getenv("MSSQL_HOST") or os.getenv("MSSQL_SERVER", "localhost")
        port = os.getenv("MSSQL_PORT", "1433")

        user = os.getenv("MSSQL_USER")
        password = os.getenv("MSSQL_PASSWORD")
        trusted_connection = _parse_bool("MSSQL_TRUSTED_CONNECTION", False)

        database = os.getenv("MSSQL_DATABASE")
        if not database:
            raise ValueError("MSSQL_DATABASE environment variable is required")

        driver = os.getenv("MSSQL_DRIVER", "ODBC Driver 17 for SQL Server")
        trust_cert = _parse_bool("MSSQL_TRUST_SERVER_CERTIFICATE", True)
        encrypt = _parse_bool("MSSQL_ENCRYPT", True)
        timeout = int(os.getenv("MSSQL_CONNECTION_TIMEOUT", "30"))
        multi_subnet = _parse_bool("MSSQL_MULTI_SUBNET_FAILOVER", False)

        if not trusted_connection and not all([user, password]):
            raise ValueError(
                "MSSQL_USER and MSSQL_PASSWORD are required when not using trusted connection. "
                "Set MSSQL_TRUSTED_CONNECTION=yes for Windows authentication."
            )

        config: Dict[str, Any] = {
            "driver": driver,
            "server": server,
            "port": port,
            "database": database,
            "trusted_connection": trusted_connection,
            "trust_server_certificate": trust_cert,
            "encrypt": encrypt,
            "timeout": timeout,
            "multi_subnet_failover": multi_subnet,
        }

        if not trusted_connection:
            config["user"] = user
            config["password"] = password

        conn_parts = [
            f"Driver={escape_odbc_value(driver)}",
            (
                f"Server={escape_odbc_value(f'{server},{port}')}"
                if port != "1433"
                else f"Server={escape_odbc_value(server)}"
            ),
            f"Database={escape_odbc_value(database)}",
            f"TrustServerCertificate={'yes' if trust_cert else 'no'}",
            f"Encrypt={'yes' if encrypt else 'no'}",
            f"Connection Timeout={timeout}",
            f"MultiSubnetFailover={'yes' if multi_subnet else 'no'}",
        ]

        if trusted_connection:
            conn_parts.append("Trusted_Connection=yes")
        else:
            conn_parts.extend(
                [
                    f"UID={escape_odbc_value(user)}",
                    f"PWD={escape_odbc_value(password)}",
                ]
            )

        connection_string = ";".join(conn_parts) + ";"

        safe_config = config.copy()
        if "password" in safe_config:
            safe_config["password"] = "***"
        logger.info("Database configuration: %s", safe_config)

        return config, connection_string


def _iter_meaningful_tokens(statement: sql.Statement):
    for token in statement.flatten():
        if token.is_whitespace or token.ttype in T.Comment:
            continue
        yield token


def _extract_first_keyword(statement: sql.Statement) -> Optional[str]:
    for token in _iter_meaningful_tokens(statement):
        value = token.normalized.upper()
        if value:
            return value
    return None


def _extract_object_identifiers(token: sql.Token) -> List[str]:
    if isinstance(token, sql.IdentifierList):
        values: List[str] = []
        for identifier in token.get_identifiers():
            values.extend(_extract_object_identifiers(identifier))
        return values

    if isinstance(token, sql.Identifier):
        if any(isinstance(child, sql.Parenthesis) for child in token.tokens):
            return []
        text = token.value.strip()
        text = re.split(r"\s+AS\s+|\s+", text, flags=re.IGNORECASE)[0]
        return [text] if text else []

    if isinstance(token, sql.Parenthesis):
        return []

    text = token.value.strip()
    return [text] if text else []


def _collect_table_references(statement: sql.Statement) -> FrozenSet[str]:
    references: set[str] = set()
    tokens = list(statement.tokens)

    for index, token in enumerate(tokens):
        normalized = token.normalized.upper() if hasattr(token, "normalized") else ""
        if normalized not in FROM_LIKE_KEYWORDS:
            continue

        next_index = index + 1
        while next_index < len(tokens):
            next_token = tokens[next_index]
            if next_token.is_whitespace or next_token.ttype in T.Comment:
                next_index += 1
                continue

            for identifier in _extract_object_identifiers(next_token):
                parts = [
                    normalize_identifier(part)
                    for part in re.findall(r"\[[^\]]+\]|[^.]+", identifier)
                ]
                parts = [part for part in parts if part]
                if len(parts) >= 2:
                    schema = parts[-2]
                    table = parts[-1]
                    references.add(normalize_table_name(schema, table))
            break

    for token in tokens:
        if isinstance(token, sql.Parenthesis):
            for inner in sqlparse.parse(token.value[1:-1]):
                references.update(_collect_table_references(inner))
        elif token.is_group and not isinstance(token, sql.Identifier):
            try:
                inner_tokens = getattr(token, "tokens", [])
            except Exception:
                inner_tokens = []
            for inner_token in inner_tokens:
                if isinstance(inner_token, sql.Parenthesis):
                    for inner in sqlparse.parse(inner_token.value[1:-1]):
                        references.update(_collect_table_references(inner))

    return frozenset(references)


def _is_metadata_query(table_refs: FrozenSet[str]) -> bool:
    if not table_refs:
        return True
    for table_ref in table_refs:
        schema, _, _ = table_ref.partition(".")
        if schema not in METADATA_SCHEMAS:
            return False
    return True


def validate_read_only_sql(
    query: str,
    allowed_schemas: FrozenSet[str],
    allowed_tables: Optional[FrozenSet[str]] = None,
    allow_metadata_only: bool = False,
    max_query_length: int = DEFAULT_MAX_QUERY_LENGTH,
) -> Tuple[bool, Optional[str]]:
    if not query or not query.strip():
        return False, "query is empty"

    if len(query) > max_query_length:
        return False, f"query exceeds max length of {max_query_length} characters"

    if "\x00" in query:
        return False, "query contains null bytes"

    if re.search(r"[\x01-\x08\x0B\x0C\x0E-\x1F]", query):
        return False, "query contains unsupported control characters"

    clean_query = QueryPreprocessor.preprocess_query(strip_sql_comments(query))
    if not clean_query:
        return False, "query is empty after removing comments"

    if re.search(r"(?im)^\s*GO\s*(?:--.*)?$", clean_query):
        return False, "GO batch separators are not allowed"

    statements = [
        statement for statement in sqlparse.parse(clean_query) if str(statement).strip()
    ]
    if len(statements) != 1:
        return False, "multiple statements are not allowed"

    statement = statements[0]
    first_keyword = _extract_first_keyword(statement)
    if first_keyword not in {"SELECT", "WITH"}:
        return False, "only SELECT and WITH statements are allowed"

    for token in _iter_meaningful_tokens(statement):
        normalized = token.normalized.upper()
        if normalized in READ_ONLY_BLOCKED_TOKENS:
            return False, f"blocked token detected: {normalized}"
        if normalized.startswith("XP_") or normalized.startswith("SP_"):
            return False, f"blocked procedure detected: {normalized}"

    table_refs = _collect_table_references(statement)
    if allow_metadata_only and not _is_metadata_query(table_refs):
        return False, "metadata-only mode blocks user-table reads"

    if not allow_metadata_only:
        for table_ref in table_refs:
            schema, _, _ = table_ref.partition(".")
            if schema not in METADATA_SCHEMAS and schema not in allowed_schemas:
                return False, f"schema not allowed: {schema}"
            if (
                allowed_tables
                and schema not in METADATA_SCHEMAS
                and table_ref not in allowed_tables
            ):
                return False, f"table not allowed: {table_ref}"

    return True, None


def is_table_allowed(schema: str, table: str, security: SecurityConfig) -> bool:
    normalized_schema = normalize_identifier(schema)
    normalized_table = normalize_identifier(table)
    full_name = normalize_table_name(normalized_schema, normalized_table)

    if normalized_schema not in security.allowed_schemas:
        return False
    if security.allowed_tables and full_name not in security.allowed_tables:
        return False
    return True


def validate_resource_access(
    schema: str,
    table: str,
    resource_type: str,
    security: SecurityConfig,
) -> Tuple[bool, Optional[str]]:
    if resource_type not in {"schema", "data"}:
        return False, f"unknown resource type: {resource_type}"

    if not is_table_allowed(schema, table, security):
        return False, f"resource not allowed: {schema}.{table}"

    if resource_type == "data" and (
        security.block_data_resources or security.allow_metadata_only
    ):
        return False, "data resources are disabled"

    return True, None


def format_select_results(
    cursor, max_rows: int
) -> Tuple[bool, List[str], Optional[str]]:
    try:
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = cursor.fetchmany(max_rows + 1)
        truncated = len(rows) > max_rows
        rows = rows[:max_rows]

        results: List[str] = []
        if columns:
            results.append("|".join(columns))
            results.append("|".join(["-" * len(col) for col in columns]))

            for row in rows:
                formatted_row = []
                for value in row:
                    formatted_row.append("NULL" if value is None else str(value))
                results.append("|".join(formatted_row))
        else:
            results.append("Query returned no columns")

        results.append("")
        results.append(f"rows_shown: {len(rows)}")
        results.append(f"rows_returned: {len(rows)}{'+' if truncated else ''}")
        results.append(f"truncated: {'true' if truncated else 'false'}")

        return True, results, None
    except Exception as exc:
        return False, [], f"Error processing query results: {exc}"


class SQLExecutor:
    """Handles SQL query execution."""

    def __init__(self, connection_string: str, security: SecurityConfig):
        self.connection_string = connection_string
        self.security = security
        self.preprocessor = QueryPreprocessor()

    def execute_query(self, query: str) -> Tuple[bool, List[str], Optional[str]]:
        request_id = build_query_fingerprint(query)
        processed_query = self.preprocessor.preprocess_query(query)

        if self.security.read_only:
            ok, reason = validate_read_only_sql(
                processed_query,
                self.security.allowed_schemas,
                self.security.allowed_tables,
                self.security.allow_metadata_only,
                self.security.max_query_length,
            )
            if not ok:
                logger.warning(
                    "Blocked query | request_id=%s reason=%s", request_id, reason
                )
                return False, [], f"Blocked by read-only policy: {reason}"

        statement_type = "UNKNOWN"
        parsed = [
            statement
            for statement in sqlparse.parse(strip_sql_comments(processed_query))
            if str(statement).strip()
        ]
        if parsed:
            statement_type = _extract_first_keyword(parsed[0]) or statement_type

        conn = None
        try:
            conn = connect(self.connection_string)
            conn.autocommit = False
            cursor = conn.cursor()
            cursor.timeout = self.security.query_timeout

            logger.info(
                "Executing query | request_id=%s statement_type=%s length=%s",
                request_id,
                statement_type,
                len(processed_query),
            )

            cursor.execute(processed_query)

            if statement_type in {"SELECT", "WITH"}:
                success, results, error = format_select_results(
                    cursor, self.security.max_rows
                )
            else:
                rows_affected = cursor.rowcount if cursor.rowcount >= 0 else 0
                success, results, error = (
                    True,
                    [f"Query executed successfully. Rows affected: {rows_affected}"],
                    None,
                )

            conn.rollback()

            logger.info(
                "Query finished | request_id=%s success=%s rows=%s",
                request_id,
                success,
                len(results),
            )
            return success, results, error
        except PyODBCError as exc:
            error_msg = str(exc)
            logger.error(
                "Database error | request_id=%s error=%s", request_id, error_msg
            )
            return False, [], error_msg
        except Exception as exc:
            error_msg = f"Unexpected error: {exc}"
            logger.error(
                "Unhandled query error | request_id=%s error=%s",
                request_id,
                exc,
                exc_info=True,
            )
            return False, [], error_msg
        finally:
            if conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass


app = Server("mssql_mcp_server")


def _build_table_filter_sql(security: SecurityConfig) -> Tuple[str, List[str]]:
    clauses = [
        "s.name IN ({})".format(", ".join("?" for _ in security.allowed_schemas))
    ]
    params: List[str] = list(sorted(security.allowed_schemas))

    if security.allowed_tables:
        table_clauses = []
        for table_ref in sorted(security.allowed_tables):
            schema, _, table = table_ref.partition(".")
            table_clauses.append("(s.name = ? AND t.name = ?)")
            params.extend([schema, table])
        clauses.append("(" + " OR ".join(table_clauses) + ")")

    return " AND ".join(clauses), params


@app.list_resources()
async def list_resources() -> List[Resource]:
    """List MSSQL tables as resources."""
    try:
        security = load_security_config()
        config, connection_string = DatabaseConfig.get_config()
        database = config["database"]
        filter_sql, params = _build_table_filter_sql(security)

        with connect(connection_string) as conn:
            with conn.cursor() as cursor:
                cursor.timeout = security.query_timeout
                cursor.execute(
                    f"""
                    SELECT TOP {security.max_tables}
                        s.name AS schema_name,
                        t.name AS table_name,
                        t.create_date,
                        t.modify_date
                    FROM sys.tables t
                    INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
                    WHERE t.type = 'U' AND {filter_sql}
                    ORDER BY s.name, t.name
                    """,
                    params,
                )
                tables = cursor.fetchall()
                logger.info(
                    "Found %s visible tables in database '%s'", len(tables), database
                )

                resources: List[Resource] = []
                for schema, table, _, _ in tables:
                    full_table_name = f"{schema}.{table}"
                    resources.append(
                        Resource(
                            uri=f"mssql://{database}/{full_table_name}/schema",
                            name=f"Schema: {full_table_name}",
                            mimeType="application/json",
                            description=f"Schema definition for table {full_table_name}",
                        )
                    )
                    if (
                        not security.block_data_resources
                        and not security.allow_metadata_only
                    ):
                        resources.append(
                            Resource(
                                uri=f"mssql://{database}/{full_table_name}/data",
                                name=f"Data: {full_table_name}",
                                mimeType="text/plain",
                                description=(
                                    f"Sample data from table {full_table_name} "
                                    f"(limited to {security.max_rows} rows)"
                                ),
                            )
                        )

                return resources
    except Exception as exc:
        logger.error("Failed to list resources: %s", exc)
        return []


@app.read_resource()
async def read_resource(uri: AnyUrl) -> str:
    """Read table schema or data."""
    uri_str = str(uri)
    logger.info("Reading resource | uri=%s", uri_str)

    if not uri_str.startswith("mssql://"):
        raise ValueError(f"Invalid URI scheme: {uri_str}")

    try:
        parts = uri_str[8:].split("/")
        if len(parts) != 3:
            raise ValueError(f"Invalid URI format: {uri_str}")

        database, table_full, resource_type = parts
        if "." in table_full:
            schema, table = table_full.split(".", 1)
        else:
            schema = "dbo"
            table = table_full

        config, connection_string = DatabaseConfig.get_config()
        if database.lower() != config["database"].lower():
            raise ValueError(f"database not allowed: {database}")

        security = load_security_config()
        ok, reason = validate_resource_access(schema, table, resource_type, security)
        if not ok:
            raise ValueError(reason)

        with connect(connection_string) as conn:
            with conn.cursor() as cursor:
                cursor.timeout = security.query_timeout
                if resource_type == "schema":
                    return await _read_table_schema(cursor, schema, table, security)
                return await _read_table_data(cursor, schema, table, security)
    except Exception as exc:
        logger.error("Error reading resource %s: %s", uri, exc)
        raise RuntimeError(f"Error reading resource: {exc}")


async def _read_table_schema(
    cursor, schema: str, table: str, security: SecurityConfig
) -> str:
    cursor.execute(
        """
        SELECT
            c.COLUMN_NAME,
            c.DATA_TYPE,
            c.CHARACTER_MAXIMUM_LENGTH,
            c.NUMERIC_PRECISION,
            c.NUMERIC_SCALE,
            c.IS_NULLABLE,
            CASE
                WHEN pk.COLUMN_NAME IS NOT NULL THEN 'YES'
                ELSE 'NO'
            END AS IS_PRIMARY_KEY
        FROM INFORMATION_SCHEMA.COLUMNS c
        LEFT JOIN (
            SELECT ku.TABLE_SCHEMA, ku.TABLE_NAME, ku.COLUMN_NAME
            FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS AS tc
            INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS ku
                ON tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
                AND tc.CONSTRAINT_NAME = ku.CONSTRAINT_NAME
        ) pk ON c.TABLE_SCHEMA = pk.TABLE_SCHEMA
            AND c.TABLE_NAME = pk.TABLE_NAME
            AND c.COLUMN_NAME = pk.COLUMN_NAME
        WHERE c.TABLE_SCHEMA = ? AND c.TABLE_NAME = ?
        ORDER BY c.ORDINAL_POSITION
        """,
        schema,
        table,
    )

    columns = cursor.fetchall()
    result = [f"Schema for {schema}.{table}:", "=" * 50, ""]

    if security.block_schema_samples:
        result.append(f"{'Column':<30} {'Type':<20} {'Nullable':<10} {'PK':<5}")
        result.append("-" * 75)
    else:
        result.append(f"{'Column':<30} {'Type':<20} {'Nullable':<10} {'PK':<5}")
        result.append("-" * 75)

    for col in columns:
        name, dtype, char_len, num_prec, num_scale, nullable, is_pk = col

        if char_len:
            type_str = f"{dtype}({char_len})"
        elif num_prec and num_scale:
            type_str = f"{dtype}({num_prec},{num_scale})"
        elif num_prec:
            type_str = f"{dtype}({num_prec})"
        else:
            type_str = dtype

        result.append(f"{name:<30} {type_str:<20} {nullable:<10} {is_pk:<5}")

    return "\n".join(result)


async def _read_table_data(
    cursor, schema: str, table: str, security: SecurityConfig
) -> str:
    cursor.execute(f"SELECT TOP {security.max_rows} * FROM [{schema}].[{table}]")
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()

    result = [
        f"Sample data from {schema}.{table} (showing up to {security.max_rows} rows):",
        "",
    ]

    if rows:
        result.append("|".join(columns))
        result.append("|".join(["-" * len(col) for col in columns]))

        for row in rows:
            formatted_row = []
            for value in row:
                if value is None:
                    formatted_row.append("NULL")
                else:
                    str_value = str(value)
                    if len(str_value) > 50:
                        str_value = str_value[:47] + "..."
                    formatted_row.append(str_value)
            result.append("|".join(formatted_row))
    else:
        result.append("(No data)")

    return "\n".join(result)


@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available MSSQL tools."""
    return [
        Tool(
            name="execute_sql",
            description="Execute a read-only SQL query on the MSSQL server",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL query to execute",
                    }
                },
                "required": ["query"],
            },
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> List[TextContent]:
    """Execute SQL commands."""
    logger.info("Calling tool: %s", name)

    if name != "execute_sql":
        raise ValueError(f"Unknown tool: {name}")

    query = arguments.get("query")
    if not query:
        raise ValueError("Query parameter is required")

    try:
        _, connection_string = DatabaseConfig.get_config()
        security = load_security_config()
        executor = SQLExecutor(connection_string, security)

        success, results, error = executor.execute_query(query)

        if success:
            return [TextContent(type="text", text="\n".join(results))]
        return [TextContent(type="text", text=f"Error: {error}")]
    except Exception as exc:
        logger.error("Error in call_tool: %s", exc, exc_info=True)
        return [TextContent(type="text", text=f"Error: {exc}")]


async def main():
    """Main entry point to run the MCP server."""
    from mcp.server.stdio import stdio_server

    logger.info("Starting MSSQL MCP Server v%s", __version__)

    try:
        config, connection_string = DatabaseConfig.get_config()
        security = load_security_config()
        logger.info(
            "Connecting to %s:%s/%s | read_only=%s",
            config["server"],
            config["port"],
            config["database"],
            security.read_only,
        )

        with connect(connection_string) as conn:
            with conn.cursor() as cursor:
                cursor.timeout = security.query_timeout
                cursor.execute("SELECT @@VERSION")
                version = cursor.fetchone()[0]
                logger.info("Connected to SQL Server: %s", version.split("\n")[0])
    except Exception as exc:
        logger.error("Failed to connect to database: %s", exc)
        sys.exit(1)

    async with stdio_server() as (read_stream, write_stream):
        try:
            await app.run(
                read_stream, write_stream, app.create_initialization_options()
            )
        except Exception as exc:
            logger.error("Server error: %s", exc, exc_info=True)
            raise


if __name__ == "__main__":
    asyncio.run(main())
