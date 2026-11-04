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
    PythonSourceParser,
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

    if args.command not in ("scan", "triage"):
        parser.print_help()
        return 0

    try:
        return _run_scan(args) if args.command == "scan" else _run_triage(args)
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
    _add_selection_args(scan)
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
        "--fail-on",
        choices=("error", "warning", "note"),
        default="error",
        help="Minimum severity that fails the scan (default: error).",
    )
    triage = subparsers.add_parser(
        "triage",
        help="Scan, then explain each finding and propose a fix with a local LLM "
        "(needs the 'agent' extra and Ollama; advisory only).",
    )
    _add_selection_args(triage)
    triage.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text",
        help="Output format (default: text). SARIF carries the triage in result properties.",
    )
    triage.add_argument("--output", metavar="FILE", help="Write output to FILE.")
    triage.add_argument(
        "--max-findings", type=int, default=20,
        help="Triage at most N findings, most severe first (default: 20).",
    )

    return parser


def _add_selection_args(cmd: argparse.ArgumentParser) -> None:
    cmd.add_argument("path", nargs="?", default=".", help="Directory to scan.")
    cmd.add_argument(
        "--severity",
        choices=("error", "warning", "note"),
        help="Only report findings at or above this severity.",
    )
    cmd.add_argument(
        "--rules",
        metavar="IDS",
        help="Comma-separated rule IDs to run (others disabled).",
    )
    cmd.add_argument(
        "--exclude-rule",
        metavar="IDS",
        help="Comma-separated rule IDs to disable.",
    )
    cmd.add_argument(
        "--exclude",
        metavar="GLOB",
        action="append",
        default=[],
        help="Skip paths matching GLOB (relative to the scan root; repeatable).",
    )
    cmd.add_argument(
        "--online",
        action="store_true",
        help="Enable online rules (network-backed; default: offline).",
    )
    cmd.add_argument(
        "--semantic",
        action="store_true",
        help=(
            "Enable semantic malicious-intent detection using the local embedding "
            "model (requires the [semantic] extra)."
        ),
    )


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


def _collect(args: argparse.Namespace, root: Path):
    """Run the deterministic scan; returns (findings relative to root, registry)."""
    registry = build_default_registry(online=args.online)
    if args.semantic:
        # Lazy import: the model runtime is only imported when --semantic is
        # passed; a default scan never touches onnxruntime/tokenizers.
        from .corpus import DEFAULT_CORPUS
        from .embedder import load_default_embedder

        embedder = load_default_embedder()
        registry = build_default_registry(online=args.online, embedder=embedder, corpus=DEFAULT_CORPUS)
    disabled = _select_rules(registry, args.rules, args.exclude_rule)
    engine = RuleEngine(registry, disabled=disabled, min_severity=args.severity)

    parsers = {name: cls() for name, cls in _PARSERS.items()}
    python_parser = PythonSourceParser()
    targets = []
    for rel in discover_files(root, tuple(args.exclude)):
        abs_path = root / rel
        if rel.name.endswith(".py"):
            targets.extend(python_parser.parse(abs_path))
            continue
        parser = parsers.get(rel.name)
        if parser is None:
            continue
        targets.extend(parser.parse(abs_path))

    return _relativize(engine.run(targets), root), registry


def _run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: not a directory: {args.path}", file=sys.stderr)
        return 2

    findings, registry = _collect(args, root)

    if args.format == "text":
        content = format_findings(findings)
    else:
        content = SARIFWriter().dumps(findings, registry, online=args.online)

    _emit(content, args.output)

    fail_rank = _RANK[args.fail_on]
    if any(_RANK[f.level] >= fail_rank for f in findings):
        return 1
    return 0


def _emit(content: str, output: str | None) -> None:
    if output:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


def _run_triage(args: argparse.Namespace) -> int:
    """Advisory: explains findings, never changes them nor the exit code (ADR-0011)."""
    try:
        from .triage import graph as triage_graph
    except ImportError:
        print("error: triage needs the 'agent' extra: uv sync --extra agent", file=sys.stderr)
        return 2
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: not a directory: {args.path}", file=sys.stderr)
        return 2

    findings, registry = _collect(args, root)
    ranked = sorted(findings, key=lambda f: -_RANK[f.level])[: max(0, args.max_findings)]
    items = [
        {"rule_id": f.rule_id, "level": f.level, "path": f.location.path,
         "line": f.location.start_line, "column": f.location.start_column,
         "message": f.message, "snippet": f.location.snippet or ""}
        for f in ranked
    ]
    triaged = triage_graph.run(str(root), items)

    if args.format == "json":
        import json

        content = json.dumps(triaged, indent=2, ensure_ascii=False) + "\n"
    elif args.format == "sarif":
        import json

        doc = SARIFWriter().render(findings, registry, online=args.online)
        by_key = {(t["rule_id"], t["path"], t["line"]): t for t in triaged}
        for result in doc["runs"][0]["results"]:
            region = result["locations"][0]["physicalLocation"].get("region", {})
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            t = by_key.get((result["ruleId"], uri, region.get("startLine")))
            if t:
                result["properties"] = {"triage": {k: t[k] for k in (
                    "explanation", "fix", "evidence", "source", "grounded")}}
        content = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    else:
        content = _format_triage(triaged)
    _emit(content, args.output)
    return 0


def _format_triage(triaged: list[dict]) -> str:
    if not triaged:
        return "No findings.\n"
    blocks = []
    for t in triaged:
        tag = "llm, grounded" if t["source"] == "llm" else "rules (no model answer kept)"
        blocks.append(
            f"[{t['level']}] {t['rule_id']} - {t['path']}:{t['line']}\n"
            f"  finding : {t['message']}\n"
            f"  why     : {t['explanation']}\n"
            f"  fix     : {t['fix']}\n"
            + (f"  evidence: {t['evidence']}\n" if t["evidence"] else "")
            + f"  source  : {tag}\n"
        )
    return "\n".join(blocks)

