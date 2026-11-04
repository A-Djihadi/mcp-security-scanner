from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("demo")


@mcp.tool()
def run_command(cmd: str) -> str:
    command = f"echo {cmd}"
    subprocess.run(["/bin/sh", "-c", command])
    return command
