"""Command-line interface for mcpsec."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from .discovery import discover_files
from .engine import RuleEngine
from .errors import McpsecError
from .model import Finding
from .parsers import (
    ClaudeDesktopConfigParser,
    McpConfigParser,
    PackageJsonParser,
    PyprojectParser,
    RequirementsParser,
    SkillMarkdownParser,
    SmitheryYamlParser,
)
from .rules import build_default_registry
from .sarif import SARIFWriter
from .text import format_findings

_RANK = {"note": 0, "warning": 1, "error": 2}

_PARSERS = {
    "mcp.json": McpConfigParser,
    ".mcp.json": McpConfigParser,
    "claude_desktop_config.json": ClaudeDesktopConfigParser,
    "package.json": PackageJsonParser,
    "requirements.txt": RequirementsParser,
    "pyproject.toml": PyprojectParser,
    "SKILL.md": SkillMarkdownParser,
    "smithery.yaml": SmitheryYamlParser,
}


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to a subcommand. Returns the exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 0

    try:
        return _run_scan(args)
    except (McpsecError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpsec",
        description="Static security scanner for MCP servers and AI agent skills.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan", help="Scan a directory and emit SARIF findings."
    )
    scan.add_argument("path", nargs="?", default=".", help="Directory to scan.")
    scan.add_argument(
        "--format",
        choices=("sarif", "text"),
        default="sarif",
        help="Output format (default: sarif).",
    )
    scan.add_argument(
        "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    scan.add_argument(
        "--severity",
        choices=("error", "warning", "note"),
        help="Only report findings at or above this severity.",
    )
    scan.add_argument(
        "--rules",
        metavar="IDS",
        help="Comma-separated rule IDs to run (others disabled).",
    )
    scan.add_argument(
        "--exclude-rule",
        metavar="IDS",
        help="Comma-separated rule IDs to disable.",
    )
    scan.add_argument(
        "--fail-on",
        choices=("error", "warning", "note"),
        default="error",
        help="Minimum severity that fails the scan (default: error).",
    )
    scan.add_argument(
        "--online",
        action="store_true",
        help="Enable online rules (network-backed; default: offline).",
    )

    return parser


def _split_ids(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _select_rules(registry, include_raw, exclude_raw):
    known = {rule.id for rule in registry}
    include = _split_ids(include_raw)
    exclude = _split_ids(exclude_raw)
    for rule_id in include + exclude:
        if rule_id not in known:
            raise McpsecError(f"unknown rule: {rule_id}")

    selected = set(include) if include else set(known)
    selected -= set(exclude)
    return known - selected


def _relativize(findings: list[Finding], root: Path) -> list[Finding]:
    root = root.resolve()
    result: list[Finding] = []
    for finding in findings:
        location = finding.location
        path = Path(location.path)
        try:
            rel = path.resolve().relative_to(root)
        except (ValueError, OSError):
            result.append(finding)
            continue
        result.append(
            replace(finding, location=replace(location, path=rel.as_posix()))
        )
    return result


def _run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: not a directory: {args.path}", file=sys.stderr)
        return 2

    registry = build_default_registry(online=args.online)
    disabled = _select_rules(registry, args.rules, args.exclude_rule)
    engine = RuleEngine(registry, disabled=disabled, min_severity=args.severity)

    parsers = {name: cls() for name, cls in _PARSERS.items()}
    targets = []
    for rel in discover_files(root):
        abs_path = root / rel
        parser = parsers.get(rel.name)
        if parser is None:
            continue
        targets.extend(parser.parse(abs_path))

    findings = engine.run(targets)
    findings = _relativize(findings, root)

    if args.format == "text":
        content = format_findings(findings)
    else:
        content = SARIFWriter().dumps(findings, registry, online=args.online)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)

    fail_rank = _RANK[args.fail_on]
    if any(_RANK[f.level] >= fail_rank for f in findings):
        return 1
    return 0
