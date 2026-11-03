"""T7 — permission-excess rules.

Covers ``MCP-shell-unrestricted``, ``MCP-allow-all``, ``MCP-broad-network``,
and ``MCP-broad-filesystem``. Severities follow the spec table in
``docs/superpowers/specs/mcp-security-scanner.md``.
"""

from __future__ import annotations

from mcpsec.model import SourceLocation, Target, TargetKind
from mcpsec.rules import (
    MCPAllowAll,
    MCPBroadFilesystem,
    MCPBroadNetwork,
    MCPShellUnrestricted,
)


def _loc(path="mcp.json", line=1, col=1):
    return SourceLocation(path=path, start_line=line, start_column=col)


def _server(
    name="srv",
    command: str | None = "npx",
    args=(),
    env=None,
    cwd=None,
    transport="stdio",
    url=None,
    field_locations=None,
    path="mcp.json",
):
    payload = {
        "command": command,
        "args": list(args),
        "env": env or {},
        "cwd": cwd,
        "transport": transport,
        "url": url,
    }
    return Target(
        kind=TargetKind.MCP_SERVER,
        name=name,
        location=_loc(path),
        payload=payload,
        field_locations=field_locations or {},
    )


# --- MCP-shell-unrestricted -------------------------------------------------


def test_shell_unrestricted_flags_generic_shell_commands():
    rule = MCPShellUnrestricted()
    for shell in ("sh", "bash", "zsh", "powershell", "pwsh", "cmd", "cmd.exe"):
        target = _server(command=shell)
        findings = rule.check(target)
        assert len(findings) == 1, shell
        assert findings[0].rule_id == "MCP-shell-unrestricted"
        assert findings[0].level == "error"


def test_shell_unrestricted_flags_absolute_path_to_shell():
    rule = MCPShellUnrestricted()
    for command in ("/bin/bash", "/usr/bin/zsh", "C:\\Windows\\System32\\cmd.exe"):
        assert len(rule.check(_server(command=command))) == 1, command


def test_shell_unrestricted_points_at_command_location():
    rule = MCPShellUnrestricted()
    command_loc = _loc("cfg/mcp.json", line=4, col=18)
    target = _server(
        name="admin",
        command="bash",
        field_locations={"command": command_loc},
        path="cfg/mcp.json",
    )
    finding = rule.check(target)[0]
    assert finding.location == command_loc
    assert finding.message == 'server "admin" runs an unrestricted shell (command "bash")'


def test_shell_unrestricted_ignores_non_shell_commands():
    rule = MCPShellUnrestricted()
    for command in ("npx", "node", "uvx", "python3", "echo", "deno"):
        assert rule.check(_server(command=command)) == [], command


def test_shell_unrestricted_ignores_missing_command():
    assert MCPShellUnrestricted().check(_server(command=None)) == []


def test_shell_unrestricted_ignores_non_server_targets():
    skill = Target(kind=TargetKind.SKILL, name="s", location=_loc(path="SKILL.md"))
    assert MCPShellUnrestricted().check(skill) == []


# --- MCP-allow-all ----------------------------------------------------------


def test_allow_all_flags_allow_all_flag():
    rule = MCPAllowAll()
    for flag in ("--allow-all", "--allow-everything", "-A"):
        target = _server(args=["run", flag])
        findings = rule.check(target)
        assert len(findings) == 1, flag
        assert findings[0].rule_id == "MCP-allow-all"
        assert findings[0].level == "error"


def test_allow_all_points_at_offending_arg():
    rule = MCPAllowAll()
    arg_loc = _loc("mcp.json", line=5, col=16)
    target = _server(
        args=["run", "--allow-all"],
        field_locations={"args": (_loc("mcp.json", 5, 16 - 0), arg_loc)},
    )
    finding = rule.check(target)[0]
    assert finding.location == arg_loc


def test_allow_all_ignores_restricted_args():
    rule = MCPAllowAll()
    target = _server(args=["--allow-read=/tmp", "--allow-net=example.com", "serve"])
    assert rule.check(target) == []


# --- MCP-broad-network ------------------------------------------------------

# NOTE: the spec table assigns MCP-broad-network level "error"; the task body's
# detection note says "warning". This test pins the design (spec table) as the
# source of truth — see PR notes.
def test_broad_network_flags_allow_net_without_host():
    rule = MCPBroadNetwork()
    finding = rule.check(_server(args=["--allow-net"]))[0]
    assert finding.rule_id == "MCP-broad-network"
    assert finding.level == "error"


def test_broad_network_points_at_offending_arg():
    rule = MCPBroadNetwork()
    arg_loc = _loc("mcp.json", line=5, col=16)
    target = _server(
        args=["--allow-net"],
        field_locations={"args": (arg_loc,)},
    )
    assert rule.check(target)[0].location == arg_loc


def test_broad_network_ignores_host_restriction():
    rule = MCPBroadNetwork()
    assert rule.check(_server(args=["--allow-net=example.com"])) == []
    assert rule.check(_server(args=["--allow-net=example.com,foo.dev"])) == []
    assert rule.check(_server(args=["serve", "--allow-read=/tmp"])) == []


# --- MCP-broad-filesystem ---------------------------------------------------


def test_broad_filesystem_flags_root_level_read_write():
    rule = MCPBroadFilesystem()
    for flag in ("--allow-read", "--allow-write", "--allow-read-write"):
        for path in ("/", "~", "C:\\", "C:/"):
            args = [f"{flag}={path}"] if path else [flag]
            findings = rule.check(_server(args=args))
            assert len(findings) == 1, (flag, path)
            assert findings[0].rule_id == "MCP-broad-filesystem"
            assert findings[0].level == "warning"


def test_broad_filesystem_flags_bare_flag_no_path():
    rule = MCPBroadFilesystem()
    for flag in ("--allow-read", "--allow-write", "--allow-read-write"):
        findings = rule.check(_server(args=[flag]))
        assert len(findings) == 1, flag


def test_broad_filesystem_ignores_restricted_paths():
    rule = MCPBroadFilesystem()
    assert rule.check(_server(args=["--allow-read=/tmp"])) == []
    assert rule.check(_server(args=["--allow-write=/home/user/data"])) == []
    assert rule.check(_server(args=["--allow-net"])) == []


# --- benign fixtures --------------------------------------------------------


def test_benign_server_triggers_nothing():
    target = _server(
        command="node",
        args=["dist/server.js", "--allow-net=api.example.com", "--allow-read=/data"],
    )
    for rule in (MCPShellUnrestricted(), MCPAllowAll(), MCPBroadNetwork(), MCPBroadFilesystem()):
        assert rule.check(target) == [], rule.id
