"""Safe synthetic MCP upstream for isolated gateway security testing.

Only exposes deterministic in-memory tools. No filesystem, shell, or network
access is provided by this server.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cerbere-staging-synthetic")
_counter = 0


@mcp.tool()
def echo(value: str) -> str:
    """Return the supplied value unchanged."""
    return value


@mcp.tool()
def increment_counter() -> int:
    """Increment and return an in-memory counter (safe side-effect sentinel)."""
    global _counter
    _counter += 1
    return _counter


@mcp.tool()
def get_counter() -> int:
    """Return the current in-memory counter without changing it."""
    return _counter


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
