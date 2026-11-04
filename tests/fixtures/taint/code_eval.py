from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def evaluate(expr: str) -> str:
    result = eval(expr)
    return result
