"""--exclude : skip fixture trees so a project can scan itself."""

from __future__ import annotations

from pathlib import Path

from mcpsec.cli import main
from mcpsec.discovery import discover_files

ROOT = Path(__file__).resolve().parent.parent


def test_exclude_prunes_a_directory_tree():
    files = discover_files(ROOT, ("tests/fixtures", ".venv"))
    assert files, "the project's own manifests are still found"
    assert not [f for f in files if f.as_posix().startswith("tests/fixtures/")]


def test_self_scan_passes_the_default_gate(capsys):
    code = main(["scan", str(ROOT), "--format", "text",
                 "--exclude", "tests/fixtures", "--exclude", ".venv"])
    assert code == 0, capsys.readouterr().out
