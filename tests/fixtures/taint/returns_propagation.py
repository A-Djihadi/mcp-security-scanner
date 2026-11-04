import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def build_command(cmd: str) -> str:
    return f"echo {cmd}"


@mcp.tool()
def run(cmd: str) -> str:
    command = build_command(cmd)
    subprocess.run(["/bin/sh", "-c", command])
    return command
