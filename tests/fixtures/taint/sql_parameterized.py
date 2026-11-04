from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def find_user(name: str) -> list:
    cursor = get_cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return []
