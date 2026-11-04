import shlex
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def run(cmd: str) -> str:
    safe = shlex.quote(cmd)
    subprocess.run(["/bin/sh", "-c", safe])
    return safe
