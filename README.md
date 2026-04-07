# MSSQL MCP Server

A Model Context Protocol (MCP) server implementation for Microsoft SQL Server. This server enables AI assistants like Claude to interact with MSSQL databases through a standardized interface.

## Features

- 🚀 **Execute Read-Only SQL**: Accepts only safe `SELECT`/`WITH` queries with validation and truncation
- 📊 **Browse Database Schema**: List only allowed tables and optionally expose schema-only resources
- 🔧 **Multi-line Query Support**: Correctly handles queries with newlines, comments, and GO statements
- 🔐 **Flexible Authentication**: Supports both Windows (trusted) and SQL authentication
- ⚙️ **Environment Configuration**: Easy setup via environment variables
- 🛡️ **Security**: Connection string encryption, certificate trust options, and secure credential handling
- 🔒 **Defense in Depth**: Designed for SQL auth users with real read-only DB permissions plus MCP-side query validation

## Installation

### From PyPI
```bash
pip install mssql-mcp-server-enhanced
```

### From Source
```bash
git clone https://github.com/combiz/mssql-mcp-server.git
cd mssql-mcp-server
pip install -e .
```

### Prerequisites

1. **Python 3.8+**
2. **ODBC Driver for SQL Server** - Install one of:
   - [ODBC Driver 17 for SQL Server](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server) (recommended)
   - [ODBC Driver 18 for SQL Server](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)

   Installation commands:
   ```bash
   # Ubuntu/Debian
   curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
   curl https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/prod.list | sudo tee /etc/apt/sources.list.d/mssql-release.list
   sudo apt-get update
   sudo apt-get install -y msodbcsql17
   
   # macOS
   brew tap microsoft/mssql-release https://github.com/Microsoft/homebrew-mssql-release
   brew update
   brew install msodbcsql17
   
   # Windows - Download installer from Microsoft
   ```

## Configuration

Configure the server using environment variables:

### Required Variables

- `MSSQL_DATABASE` - The database name to connect to

### Connection Variables

- `MSSQL_HOST` or `MSSQL_SERVER` - Server hostname (default: `localhost`)
- `MSSQL_PORT` - Server port (default: `1433`)

### Authentication Variables

For SQL Authentication:
- `MSSQL_USER` - Username
- `MSSQL_PASSWORD` - Password
- `MSSQL_TRUSTED_CONNECTION` - Set to `no` (default: `no`)

For Windows Authentication:
- `MSSQL_TRUSTED_CONNECTION` - Set to `yes`
- No username/password needed

### Optional Variables

- `MSSQL_DRIVER` - ODBC driver name (default: `ODBC Driver 17 for SQL Server`)
- `MSSQL_TRUST_SERVER_CERTIFICATE` - Trust server certificate (default: `yes`)
- `MSSQL_ENCRYPT` - Encrypt connection (default: `yes`)
- `MSSQL_CONNECTION_TIMEOUT` - Connection timeout in seconds (default: `30`)
- `MSSQL_MULTI_SUBNET_FAILOVER` - Enable multi-subnet failover (default: `no`)

### Read-Only Security Variables

- `MSSQL_READ_ONLY` - Enable strict read-only validation (default: `true`)
- `MSSQL_MAX_ROWS` - Maximum rows returned by `execute_sql` or sample data reads (default: `200`)
- `MSSQL_MAX_TABLES` - Maximum tables exposed as MCP resources (default: `100`)
- `MSSQL_QUERY_TIMEOUT` - Per-query execution timeout in seconds (default: `30`)
- `MSSQL_ALLOWED_SCHEMAS` - Comma-separated schema allowlist (default: `dbo`)
- `MSSQL_ALLOWED_TABLES` - Optional comma-separated fully qualified table allowlist, for example `dbo.Clientes,dbo.Ordenes`
- `MSSQL_BLOCK_SCHEMA_SAMPLES` - Reduce schema output to structural metadata only (default: `true`)
- `MSSQL_BLOCK_DATA_RESOURCES` - Disable `.../data` MCP resources (default: `true`)
- `MSSQL_ALLOW_METADATA_ONLY` - Allow metadata queries only, blocking user-table reads (default: `false`)
- `MSSQL_MAX_QUERY_LENGTH` - Maximum accepted query length in characters (default: `20000`)

## Usage

### As a Standalone Server

```bash
# Set environment variables
export MSSQL_SERVER=your-server.database.windows.net
export MSSQL_DATABASE=your-database
export MSSQL_USER=your-username
export MSSQL_PASSWORD=your-password

# Run the server
python -m mssql_mcp_server.server
```

### With MCP-Compatible Clients

Add to your MCP configuration file:

**Claude Desktop**:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

**Claude Code**: See Claude Code documentation for configuration location

**Cursor**: Add to your Cursor MCP settings

```json
{
  "mcpServers": {
    "mssql": {
      "command": "python",
      "args": ["-m", "mssql_mcp_server.server"],
      "env": {
        "MSSQL_SERVER": "your-server.database.windows.net",
        "MSSQL_DATABASE": "your-database",
        "MSSQL_USER": "your-username",
        "MSSQL_PASSWORD": "your-password"
      }
    }
  }
}
```

### Example Configurations

#### Azure SQL Database
```bash
export MSSQL_SERVER=myserver.database.windows.net
export MSSQL_DATABASE=mydatabase
export MSSQL_USER=myuser@myserver
export MSSQL_PASSWORD=mypassword
export MSSQL_ENCRYPT=yes
export MSSQL_TRUST_SERVER_CERTIFICATE=no
```

#### Local SQL Server with Windows Authentication
```bash
export MSSQL_SERVER=localhost
export MSSQL_DATABASE=mydatabase
export MSSQL_TRUSTED_CONNECTION=yes
```

#### SQL Server on Non-Standard Port
```bash
export MSSQL_SERVER=myserver.company.com
export MSSQL_PORT=1434
export MSSQL_DATABASE=mydatabase
export MSSQL_USER=sa
export MSSQL_PASSWORD=mypassword
```

#### MCP Configuration with Virtual Environment
For use with Claude Desktop, Claude Code, Cursor, or any MCP-compatible client. If you're using a Python virtual environment, specify the full path to the Python executable:

```json
{
  "mcpServers": {
    "mssql": {
      "command": "/path/to/your/venv/bin/python",
      "args": ["-m", "mssql_mcp_server.server"],
      "env": {
        "MSSQL_SERVER": "your-server-name",
        "MSSQL_DATABASE": "your-database",
        "MSSQL_DRIVER": "ODBC Driver 17 for SQL Server",
        "MSSQL_TRUST_SERVER_CERTIFICATE": "yes",
        "MSSQL_TRUSTED_CONNECTION": "yes",
        "MSSQL_ENCRYPT": "yes",
        "MSSQL_CONNECTION_TIMEOUT": "60",
        "MSSQL_PORT": "1433"
      }
    }
  }
}
```

## Available Tools

### execute_sql

Execute any SQL query on the connected database.
Execute validated read-only SQL on the connected database.

**Parameters:**
- `query` (string, required): The SQL query to execute

**Examples:**

```sql
SELECT TOP 20 * FROM dbo.Users WHERE active = 1

WITH recent_orders AS (
    SELECT TOP 50 user_id, created_at
    FROM dbo.Orders
    ORDER BY created_at DESC
)
SELECT user_id, COUNT(*) AS recent_order_count
FROM recent_orders
GROUP BY user_id
```

## Available Resources

The server exposes database tables as resources:

- **Schema Resource**: `mssql://database/schema.table/schema`
  - Shows table structure, column types, constraints
  
- **Data Resource**: `mssql://database/schema.table/data`
  - Disabled by default and only available when `MSSQL_BLOCK_DATA_RESOURCES=false`

## Query Preprocessing

The server automatically handles:

- ✅ Multi-line queries with proper newline handling
- ✅ SQL comments (both `--` and `/* */` styles)
- ✅ GO batch separators (executes first batch only with warning)
- ✅ String literals with embedded newlines
- ✅ Excessive whitespace cleanup

## Error Handling

The server provides detailed error messages for:

- Connection failures
- Authentication errors
- SQL syntax errors
- Query execution errors
- Invalid configurations

## Security Considerations

1. **Credentials**: Use environment variables or secure credential stores. Never hardcode credentials.
2. **Permissions**: Use database users with minimal required permissions.
3. **Connection Encryption**: Enable `MSSQL_ENCRYPT` for production environments.
4. **Certificate Validation**: Set `MSSQL_TRUST_SERVER_CERTIFICATE=no` for production.
5. **Read-Only SQL User**: Use a real SQL login with read-only permissions on the allowed schemas/tables.
6. **Query Validation**: The MCP layer only accepts a single `SELECT` or `WITH` statement, blocks dangerous tokens, rejects multi-statement batches, and limits rows/timeouts.
7. **Metadata Exposure**: Keep `MSSQL_BLOCK_DATA_RESOURCES=true` unless sample rows are explicitly needed.

## Development

### Running Tests
```bash
pip install -e ".[dev]"
pytest
```

### Code Formatting
```bash
black mssql_mcp_server
flake8 mssql_mcp_server
mypy mssql_mcp_server
```

## Troubleshooting

### Connection Issues

1. **"ODBC Driver X for SQL Server not found"**
   - Install the ODBC driver (see Prerequisites)
   - Update `MSSQL_DRIVER` to match your installed driver

2. **"Login failed for user"**
   - Verify credentials
   - Check if SQL authentication is enabled on the server
   - For Azure SQL, ensure username includes server name: `user@server`

3. **"Cannot open server requested by the login"**
   - Verify server name/address
   - Check firewall rules
   - Ensure SQL Server is accepting TCP/IP connections

### Query Issues

1. **"Incorrect syntax near 'GO'"**
   - The server handles GO statements by executing only the first batch
   - Split multi-batch scripts into separate queries

2. **Hanging queries**
   - Check for unclosed transactions
   - Verify query doesn't have syntax errors related to newlines
   - Monitor query execution time with `MSSQL_CONNECTION_TIMEOUT`

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Built on the [Model Context Protocol](https://github.com/anthropics/mcp)
- Uses [pyodbc](https://github.com/mkleehammer/pyodbc) for database connectivity
