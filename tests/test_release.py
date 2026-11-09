"""T24 — release automation: tag↔version consistency check.

Tests the exact function CI runs: ``verify_tag_version`` in
``scripts/check_tag_version.py`` (loaded by path so the test exercises the
shipped script, not a duplicate).
"""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "check_tag_version.py"


def _load_check_module():
    spec = importlib.util.spec_from_file_location("check_tag_version", _SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load_check_module()


def _project_version() -> str:
    """Read the current project version from pyproject.toml (single source of truth)."""
    with (_ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_tag_with_leading_v_matches_version():
    assert check.verify_tag_version("v0.1.0", "0.1.0") is True


def test_tag_mismatch_is_rejected():
    assert check.verify_tag_version("v0.1.1", "0.1.0") is False


def test_tag_without_leading_v_matches_version():
    assert check.verify_tag_version("0.1.0", "0.1.0") is True


def test_read_project_version_reads_pyproject():
    assert check.read_project_version(_ROOT / "pyproject.toml") == _project_version()


def test_main_exits_zero_on_match(capsys):
    version = _project_version()
    assert check.main([f"v{version}"]) == 0
    captured = capsys.readouterr()
    assert "matches" in captured.out


def test_main_exits_nonzero_on_mismatch(capsys):
    version = _project_version()
    assert check.main([f"v{version}.post1"]) == 1
    captured = capsys.readouterr()
    assert "does not match" in captured.err
