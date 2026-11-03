"""Command-line interface for mcpsec."""

from __future__ import annotations

import argparse
import json


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to a subcommand. Returns the exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)

    parser.print_help()
    return 0


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

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    # T1 skeleton: discovery + parsers + rules land in later tickets. For now a
    # scan of any directory emits an empty, structurally-valid SARIF document.
    document: dict = {"version": "2.1.0", "runs": [{"results": []}]}
    print(json.dumps(document))
    return 0
