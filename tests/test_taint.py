"""T22 — Python taint/flow analysis (sources, sinks, propagators, sanitizers)."""

from __future__ import annotations

import json
from pathlib import Path

from mcpsec import cli
from mcpsec.discovery import discover_files
from mcpsec.engine import RuleEngine
from mcpsec.model import RuleRegistry, SourceLocation, Target, TargetKind
from mcpsec.parsers import PythonSourceParser
from mcpsec.rules import (
    FLOWCodeEval,
    FLOWShellInjection,
    FLOWSqlInjection,
    build_default_registry,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "taint"

_FLOW_RULES = [FLOWShellInjection, FLOWSqlInjection, FLOWCodeEval]


def _target(path: Path) -> Target:
    targets = PythonSourceParser().parse(path)
    assert len(targets) == 1, f"expected one target for {path.name}, got {len(targets)}"
    return targets[0]


def _target_from_source(source: str) -> Target:
    return Target(
        kind=TargetKind.PYTHON_SOURCE,
        name="inline.py",
        location=SourceLocation(path="inline.py"),
        payload={"source": source},
    )


# --- Parser seam ------------------------------------------------------------


def test_python_source_parser_emits_one_python_source_target():
    target = _target(FIXTURES / "benign.py")
    assert target.kind is TargetKind.PYTHON_SOURCE
    assert "subprocess.run" in target.payload["source"]


def test_discovery_finds_python_but_skips_vendored_and_cache_dirs(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    venv = tmp_path / ".venv" / "Lib" / "site-packages"
    venv.mkdir(parents=True)
    (venv / "dep.py").write_text("x = 1\n", encoding="utf-8")
    pycache = tmp_path / "__pycache__"
    pycache.mkdir(parents=True)
    (pycache / "app.cpython-313.pyc").write_bytes(b"\x00")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("// js", encoding="utf-8")

    found = discover_files(tmp_path)
    assert [p.as_posix() for p in found] == ["app.py"]


# --- Sources / sinks --------------------------------------------------------


def test_tainted_param_via_fstring_into_subprocess_triggers_shell_injection():
    findings = FLOWShellInjection().check(_target(FIXTURES / "shell_injection.py"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "FLOW-shell-injection"
    assert finding.level == "error"
    assert finding.location.start_line == 10
    assert finding.location.start_column == 5
    assert "subprocess.run" in finding.message


def test_tainted_value_reaches_sql_execute_triggers_sql_injection():
    findings = FLOWSqlInjection().check(_target(FIXTURES / "sql_injection.py"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "FLOW-sql-injection"
    assert finding.level == "error"
    assert finding.location.start_line == 10
    assert finding.location.start_column == 5


def test_parameterized_sql_execute_does_not_fire():
    assert FLOWSqlInjection().check(_target(FIXTURES / "sql_parameterized.py")) == []


def test_tainted_value_reaches_eval_triggers_code_eval_warning():
    findings = FLOWCodeEval().check(_target(FIXTURES / "code_eval.py"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "FLOW-code-eval"
    assert finding.level == "warning"
    assert finding.location.start_line == 8
    assert finding.location.start_column == 14


def test_taint_propagates_through_function_returns():
    findings = FLOWShellInjection().check(_target(FIXTURES / "returns_propagation.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "FLOW-shell-injection"
    assert findings[0].location.start_line == 15


def test_propagator_variety_join_format_percent_concat_indexing():
    source = '''import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def run(cmd: str) -> None:
    a = " ".join(["echo", cmd])
    os.system(a)
    b = "echo {}".format(cmd)
    os.system(b)
    c = "echo %s" % cmd
    os.system(c)
    d = "echo " + cmd
    os.system(d)
    e = cmd[0]
    os.system(e)
'''
    findings = FLOWShellInjection().check(_target_from_source(source))
    assert [f.location.start_line for f in findings] == [8, 10, 12, 14, 16]


def test_executemany_tainted_query_fires():
    source = '''import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def load(rows: str) -> None:
    con = sqlite3.connect(":memory:")
    query = f"INSERT INTO t VALUES ({rows})"
    con.executemany(query, [])
'''
    findings = FLOWSqlInjection().check(_target_from_source(source))
    assert len(findings) == 1
    assert "executemany" in findings[0].message


def test_executemany_parameterized_query_does_not_fire():
    source = '''import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def load(rows: str) -> None:
    con = sqlite3.connect(":memory:")
    con.executemany("INSERT INTO t VALUES (?)", [(rows,)])
'''
    assert FLOWSqlInjection().check(_target_from_source(source)) == []


def test_request_params_attribute_is_a_source():
    findings = FLOWShellInjection().check(_target(FIXTURES / "request_params.py"))
    assert len(findings) == 1
    assert findings[0].rule_id == "FLOW-shell-injection"
    assert findings[0].location.start_line == 6


# --- Sanitizers -------------------------------------------------------------


def test_recognized_sanitizer_blocks_taint_propagation():
    assert FLOWShellInjection().check(_target(FIXTURES / "sanitized.py")) == []


def test_benign_fixture_yields_no_findings():
    for rule_cls in _FLOW_RULES:
        assert rule_cls().check(_target(FIXTURES / "benign.py")) == []


# --- Determinism ------------------------------------------------------------


def test_analysis_is_pure_deterministic_sorted_and_deduped():
    targets = [
        PythonSourceParser().parse(path)[0] for path in sorted(FIXTURES.glob("*.py"))
    ]
    registry = build_default_registry()
    engine = RuleEngine(registry)

    first = engine.run(targets)
    second = engine.run(targets)

    assert first == second
    keys = [(f.location.path, f.location.start_line, f.rule_id) for f in first]
    assert keys == sorted(keys)
    assert len(keys) == len(set(keys))


def test_flow_rules_registered_in_default_registry():
    registry = build_default_registry()
    assert "FLOW-shell-injection" in registry
    assert "FLOW-sql-injection" in registry
    assert "FLOW-code-eval" in registry


# --- CLI end-to-end ---------------------------------------------------------


def test_cli_scans_python_sources_and_is_byte_deterministic(tmp_path):
    out1 = tmp_path / "one.sarif"
    out2 = tmp_path / "two.sarif"

    code1 = cli.main(["scan", str(FIXTURES), "--output", str(out1)])
    code2 = cli.main(["scan", str(FIXTURES), "--output", str(out2)])

    assert code1 == 1  # error-level FLOW findings present
    assert code2 == 1
    assert out1.read_bytes() == out2.read_bytes()

    doc = json.loads(out1.read_text(encoding="utf-8"))
    results = doc["runs"][0]["results"]
    got = [
        (
            r["ruleId"],
            r["level"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in results
    ]
    assert got == [
        ("FLOW-code-eval", "warning", "code_eval.py", 8),
        ("FLOW-shell-injection", "error", "request_params.py", 6),
        ("FLOW-shell-injection", "error", "returns_propagation.py", 15),
        ("FLOW-shell-injection", "error", "shell_injection.py", 10),
        ("FLOW-sql-injection", "error", "sql_injection.py", 10),
    ]
