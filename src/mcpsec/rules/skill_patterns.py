"""Skill-body rules: shell execution, remote code exec, obfuscation, SQL.

Pure, deterministic checks over a ``skill`` target's line-indexed body.
Severities follow the spec taxonomy in
``docs/superpowers/specs/mcp-security-scanner.md``.
"""

from __future__ import annotations

import re

from ..model import Finding, Target, TargetKind

# A shell invocation: subprocess / os.system / os.popen / backticks / `sh -c`.
_SHELL_CALL = re.compile(
    r"(?:\bsubprocess\b|\bos\.(?:system|popen)\b|`[^`\n]*`|"
    r"(?:^|\s)(?:sh|bash|zsh|ksh|dash)\s+-c\b)"
)
# Interpolation signals: f-string, .format(...), or a string literal + concat.
_FSTRING = re.compile(r"\bf['\"]")
_FORMAT = re.compile(r"\.format\(")
_CONCAT = re.compile(r"(['\"])[^'\"]*\1\s*\+")

_FETCH = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b", re.IGNORECASE)
_PIPE_TO_SHELL = re.compile(
    r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ksh|dash|powershell|pwsh|cmd|eval|"
    r"Invoke-Expression)\b",
    re.IGNORECASE,
)
_EVAL_FETCH = re.compile(r"\beval\s*\(\s*fetch\s*\(", re.IGNORECASE)

_BASE64_DECODE = re.compile(r"\bbase64\s+(?:-d|-D|--decode)\b", re.IGNORECASE)

_SQL_KEYWORD = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|ALTER|CREATE|EXEC|"
    r"EXECUTE)\b",
    re.IGNORECASE,
)


def _body_lines(target: Target):
    lines = target.payload.get("body_lines") or []
    locs = target.field_locations.get("body")
    if isinstance(locs, (tuple, list)) and len(locs) == len(lines):
        return zip(lines, locs)
    return ((line, target.location) for line in lines)


class SKLShellExecution:
    id = "SKL-shell-execution"
    level = "warning"
    short_description = "Skill invokes a shell with interpolated input."

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.SKILL:
            return []
        findings: list[Finding] = []
        for line, location in _body_lines(target):
            if _SHELL_CALL.search(line) and (
                _FSTRING.search(line) or _FORMAT.search(line) or _CONCAT.search(line)
            ):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        level=self.level,
                        message=(
                            f'skill "{target.name}" invokes a shell with '
                            f'interpolated input'
                        ),
                        location=location,
                    )
                )
        return findings


class SKLRemoteCodeExec:
    id = "SKL-remote-code-exec"
    level = "error"
    short_description = "Skill pipes remote content to a shell."

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.SKILL:
            return []
        findings: list[Finding] = []
        for line, location in _body_lines(target):
            if (_FETCH.search(line) and _PIPE_TO_SHELL.search(line)) or _EVAL_FETCH.search(
                line
            ):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        level=self.level,
                        message=f'skill "{target.name}" pipes remote content to a shell',
                        location=location,
                    )
                )
        return findings


class SKLObfuscatedCommand:
    id = "SKL-obfuscated-command"
    level = "warning"
    short_description = "Skill decodes a base64 payload in a shell command."

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.SKILL:
            return []
        findings: list[Finding] = []
        for line, location in _body_lines(target):
            if _BASE64_DECODE.search(line):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        level=self.level,
                        message=(
                            f'skill "{target.name}" decodes a base64 payload in a '
                            f'shell command'
                        ),
                        location=location,
                    )
                )
        return findings


class SKLSqlConcatenation:
    id = "SKL-sql-concatenation"
    level = "error"
    short_description = "Skill builds a SQL query by string interpolation."

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.SKILL:
            return []
        findings: list[Finding] = []
        for line, location in _body_lines(target):
            if not _SQL_KEYWORD.search(line):
                continue
            if (_FSTRING.search(line) and "{" in line) or _CONCAT.search(line):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        level=self.level,
                        message=(
                            f'skill "{target.name}" builds a SQL query by string '
                            f'interpolation'
                        ),
                        location=location,
                    )
                )
        return findings
