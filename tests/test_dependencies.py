"""T4 — dependency manifest parsers (package.json, requirements.txt, pyproject.toml)."""

from __future__ import annotations

from pathlib import Path

from mcpsec.model import TargetKind
from mcpsec.parsers import PackageJsonParser, PyprojectParser, RequirementsParser

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _deps(targets):
    return [t for t in targets if t.kind is TargetKind.DEPENDENCY]


def _servers(targets):
    return [t for t in targets if t.kind is TargetKind.MCP_SERVER]


def test_package_json_yields_servers_and_dependencies():
    targets = PackageJsonParser().parse(FIXTURES / "package.json")

    servers = _servers(targets)
    assert [s.name for s in servers] == ["tool"]
    assert servers[0].payload["command"] == "node"

    deps = {d.name: d for d in _deps(targets)}
    assert set(deps) == {"express", "lodash", "left-pad", "typescript", "vitest"}
    assert deps["lodash"].payload["pinned"] is True
    assert deps["express"].payload["pinned"] is False  # ^ range
    assert deps["left-pad"].payload["pinned"] is False  # wildcard
    assert deps["typescript"].payload["pinned"] is False  # ~ range
    assert deps["vitest"].payload["pinned"] is False  # latest


def test_requirements_pinned_only_for_eq_specs():
    deps = {d.name: d for d in _deps(RequirementsParser().parse(FIXTURES / "requirements.txt"))}
    assert set(deps) == {"requests", "flask", "numpy", "django", "pytest"}
    assert deps["requests"].payload["pinned"] is True  # ==
    assert deps["numpy"].payload["pinned"] is True  # ===
    assert deps["flask"].payload["pinned"] is False  # >=
    assert deps["pytest"].payload["pinned"] is False  # ~=
    assert deps["django"].payload["pinned"] is False  # no spec


def test_requirements_records_declaration_line():
    deps = RequirementsParser().parse(FIXTURES / "requirements.txt")
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].location.start_line == 2
    assert by_name["django"].location.start_line == 5
    assert by_name["requests"].payload["source"] == "requests==2.31.0"


def test_pyproject_yields_project_and_optional_dependencies():
    deps = {d.name: d for d in _deps(PyprojectParser().parse(FIXTURES / "pyproject.toml"))}
    assert set(deps) == {"requests", "flask", "click", "pytest", "ruff", "sphinx"}
    assert deps["requests"].payload["pinned"] is True
    assert deps["pytest"].payload["pinned"] is True
    assert deps["flask"].payload["pinned"] is False
    assert deps["click"].payload["pinned"] is False
    assert deps["ruff"].payload["pinned"] is False
    assert deps["sphinx"].payload["pinned"] is False


def test_requirements_without_pin_and_npm_wildcards(tmp_path):
    # npm-style unpinned forms, exercised through package.json
    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"dependencies": {"a": "1.2.3", "b": "^1.0.0", "c": "~1.0.0", "d": "*", "e": "latest", "f": ""}}',
        encoding="utf-8",
    )
    deps = {d.name: d for d in _deps(PackageJsonParser().parse(pkg))}
    assert deps["a"].payload["pinned"] is True
    assert deps["b"].payload["pinned"] is False
    assert deps["c"].payload["pinned"] is False
    assert deps["d"].payload["pinned"] is False
    assert deps["e"].payload["pinned"] is False
    assert deps["f"].payload["pinned"] is False

    # python-style pins, exercised through requirements.txt
    req = tmp_path / "requirements.txt"
    req.write_text("x==1.2.3\ny===1.0\nz\n", encoding="utf-8")
    rdeps = {d.name: d for d in _deps(RequirementsParser().parse(req))}
    assert rdeps["x"].payload["pinned"] is True
    assert rdeps["y"].payload["pinned"] is True
    assert rdeps["z"].payload["pinned"] is False


def test_unrelated_manifests_return_empty(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "no-deps-here"}', encoding="utf-8")
    assert PackageJsonParser().parse(pkg) == []

    req = tmp_path / "requirements.txt"
    req.write_text("# only a comment\n", encoding="utf-8")
    assert RequirementsParser().parse(req) == []
