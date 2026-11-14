"""A harmless MCP server used to test that the proxy is transparent."""

from mcp.server import MCPServer

server = MCPServer("echo")


@server.tool()
def echo(text: str) -> str:
    """Return the text unchanged."""
    return text


@server.tool()
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


@server.resource("fixture://greeting")
def greeting() -> str:
    """A static resource, to check that non-tool methods pass through."""
    return "hello from the echo server"


if __name__ == "__main__":
    server.run("stdio")
