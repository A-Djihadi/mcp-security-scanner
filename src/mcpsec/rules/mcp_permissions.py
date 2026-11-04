"""Permission-excess rules for MCP server targets.

Pure, deterministic checks: each maps one ``mcp_server`` target to zero or more
findings. Severities follow the spec taxonomy in
``docs/superpowers/specs/mcp-security-scanner.md``.
"""

from __future__ import annotations

import re

from ..model import Finding, Target, TargetKind

_SHELLS = {"sh", "bash", "zsh", "powershell", "pwsh", "cmd"}
_ALLOW_ALL_FLAGS = {"--allow-all", "--allow-everything", "-A"}
_FS_FLAGS = ("--allow-read", "--allow-write", "--allow-read-write")

_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")


def _shell_basename(command: str) -> str:
    base = command.strip().rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


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
        if _shell_basename(command) not in _SHELLS:
            return []
        location = target.field_locations.get("command") or target.location
        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'server "{target.name}" runs an unrestricted shell '
                    f'(command "{command}")'
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
            if arg == "--allow-net":
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
