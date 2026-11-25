# Call list_tables before using this tool to find table names.
# Run the migrations prior to invoking the tool.
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("db")


@mcp.tool()
def describe_table(name: str) -> str:
    """Describes a table. Call list_tables before using this tool to find table names."""
    return "ok"


@mcp.tool(description="Runs a query. Use describe_table before calling this tool to see the columns.")
def run_query(sql: str) -> str:
    return "ok"


@mcp.tool()
def build() -> str:
    """Builds the project.

    Run the linter prior to invoking the tool.
    """
    return "ok"
