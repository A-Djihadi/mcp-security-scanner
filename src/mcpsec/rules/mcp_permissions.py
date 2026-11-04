"""Permission-excess rules for MCP server targets.

Pure, deterministic checks: each maps one ``mcp_server`` target to zero or more
findings. Severities follow the spec taxonomy in
``docs/superpowers/specs/mcp-security-scanner.md``.
"""

from __future__ import annotations

import re

from ..model import Finding, Target, TargetKind

_SHELLS = {
    "sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "fish", "csh", "tcsh",
    "powershell", "pwsh", "cmd",
}
# Launchers that run another program: the real command is their first operand.
_WRAPPERS = {"env", "sudo", "doas", "nohup", "stdbuf", "exec", "command"}
# Interpreters whose flag runs inline code passed on the command line.
_INLINE_CODE = {
    "python": {"-c"}, "python3": {"-c"}, "py": {"-c"}, "pypy3": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"}, "bun": {"-e", "--eval"},
    "deno": {"eval"}, "ruby": {"-e"}, "perl": {"-e", "-E"}, "php": {"-r"},
}
_ALLOW_ALL_FLAGS = {"--allow-all", "--allow-everything", "-A"}
_FS_FLAGS = ("--allow-read", "--allow-write", "--allow-read-write")

_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")


def _shell_basename(command: str) -> str:
    base = command.strip().rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    base = base.removesuffix(".exe")
    return base


def _effective_command(command: str, args: list) -> tuple[str, list]:
    """Unwrap launchers (``env bash -c``, ``sudo sh``) to the program they run."""
    base, rest = _shell_basename(command), list(args)
    while base in _WRAPPERS and rest:
        head = rest.pop(0)
        if not isinstance(head, str) or head.startswith("-") or "=" in head:
            continue  # option or VAR=value assignment of the launcher
        base = _shell_basename(head)
    return base, rest


def _is_broad_path(path: str) -> bool:
    path = path.strip()
    if path in ("", "/", "~"):
        return True
    return bool(_DRIVE_ROOT.match(path))


def _args_with_locations(target: Target):
    args = target.payload.get("args") or []
    locs = target.field_locations.get("args")
    if isinstance(locs, (tuple, list)) and len(locs) == len(args):
        return zip(args, locs)
    return ((arg, target.location) for arg in args)


class MCPShellUnrestricted:
    id = "MCP-shell-unrestricted"
    level = "error"
    short_description = "MCP server runs an unrestricted shell interpreter."
    online = False

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        command = target.payload.get("command")
        if not isinstance(command, str) or not command:
            return []
        base, _ = _effective_command(command, target.payload.get("args") or [])
        if base not in _SHELLS:
            return []
        location = target.field_locations.get("command") or target.location
        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'server "{target.name}" runs an unrestricted shell '
                    f'(command "{command}"'
                    + (f" -> {base})" if base != _shell_basename(command) else ")")
                ),
                location=location,
            )
        ]


class MCPAllowAll:
    id = "MCP-allow-all"
    level = "error"
    short_description = "MCP server grants unrestricted permissions."
    online = False

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        findings: list[Finding] = []
        for arg, location in _args_with_locations(target):
            if arg in _ALLOW_ALL_FLAGS:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        level=self.level,
                        message=(
                            f'server "{target.name}" grants all permissions ({arg})'
                        ),
                        location=location,
                    )
                )
        return findings


class MCPBroadNetwork:
    id = "MCP-broad-network"
    level = "error"
    short_description = "MCP server allows unrestricted network access."
    online = False

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        findings: list[Finding] = []
        for arg, location in _args_with_locations(target):
            if arg in ("--allow-net", "--allow-net="):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        level=self.level,
                        message=(
                            f'server "{target.name}" allows unrestricted network '
                            f'access ({arg})'
                        ),
                        location=location,
                    )
                )
        return findings


class MCPBroadFilesystem:
    id = "MCP-broad-filesystem"
    level = "warning"
    short_description = "MCP server grants broad filesystem access."
    online = False

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        findings: list[Finding] = []
        for arg, location in _args_with_locations(target):
            flag, _, path = arg.partition("=")
            if flag not in _FS_FLAGS:
                continue
            broad = _is_broad_path(path) if "=" in arg else True
            if broad:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        level=self.level,
                        message=(
                            f'server "{target.name}" grants broad filesystem '
                            f'access ({arg})'
                        ),
                        location=location,
                    )
                )
        return findings


class MCPInlineCode:
    id = "MCP-inline-code"
    level = "warning"
    short_description = (
        "MCP server runs inline code passed on the command line (python -c, node -e)."
    )
    online = False

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.MCP_SERVER:
            return []
        command = target.payload.get("command")
        if not isinstance(command, str) or not command:
            return []
        base, rest = _effective_command(command, target.payload.get("args") or [])
        flags = _INLINE_CODE.get(base)
        if not flags or not any(isinstance(a, str) and a in flags for a in rest):
            return []
        location = target.field_locations.get("command") or target.location
        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'server "{target.name}" runs inline code with {base} '
                    "(code is not reviewable as a file)"
                ),
                location=location,
            )
        ]
