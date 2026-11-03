"""T1 — project scaffolding & CLI skeleton."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from mcpsec import cli


def test_help_lists_scan_subcommand(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    assert "scan" in capsys.readouterr().out


def test_scan_empty_dir_exits_zero(tmp_path, capsys):
    code = cli.main(["scan", str(tmp_path)])
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["results"] == []


def test_scan_dir_without_recognized_files_produces_empty_results(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("nothing to scan here\n")
    code = cli.main(["scan", str(tmp_path)])
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_pyproject_declares_python_313_and_dependency_policy():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    assert data["project"]["requires-python"] == ">=3.13"

    runtime = [d.lower() for d in data["project"]["dependencies"]]
    assert runtime == ["pyyaml>=6.0.3"], "PyYAML must be the sole runtime dependency"

    dev = [d.lower() for d in data["dependency-groups"]["dev"]]
    assert any(d.startswith("pytest") for d in dev)

    assert data["project"]["scripts"]["mcpsec"] == "mcpsec.cli:main"
