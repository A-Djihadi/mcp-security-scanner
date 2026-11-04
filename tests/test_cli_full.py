"""T10 — full CLI: flags, exit codes, text formatter, E2E determinism."""

from __future__ import annotations

import json
from pathlib import Path

from mcpsec import cli

FIXTURES = Path(__file__).resolve().parent / "fixtures"
E2E = FIXTURES / "e2e"


def _run(argv, capsys=None):
    code = cli.main(argv)
    if capsys is None:
        return code
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_text_format_prints_one_line_per_finding(capsys):
    code, out, _ = _run(["scan", str(E2E), "--format", "text"], capsys)
    assert code == 1  # error-level findings present
    lines = out.splitlines()
    assert lines == [
        ('[error] MCP-shell-unrestricted — mcp.json:4:18 — '
            'server "shell-runner" runs an unrestricted shell (command "bash")'),
        ('[error] MCP-allow-all — mcp.json:9:16 — '
            'server "open-grants" grants all permissions (--allow-all)'),
        ('[error] SKL-remote-code-exec — profiles/alice/skills/evil/SKILL.md:6:1 — '
            'skill "evil" pipes remote content to a shell'),
        ('[warning] DEP-unpinned — requirements.txt:1:1 — '
            'dependency "requests" is unpinned (no version spec)'),
    ]


def test_output_writes_sarif_and_keeps_stdout_clean(tmp_path, capsys):
    out = tmp_path / "results.sarif"
    code, stdout, _ = _run(["scan", str(E2E), "--output", str(out)], capsys)
    assert code == 1
    assert stdout == ""
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert len(results) == 4


def test_rules_restrict_to_named_rules(capsys):
    _, out, _ = _run(["scan", str(E2E), "--format", "text", "--rules", "DEP-unpinned"], capsys)
    lines = out.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("[warning] DEP-unpinned")


def test_exclude_rule_removes_named_rule(capsys):
    _, out, _ = _run(
        ["scan", str(E2E), "--format", "text", "--exclude-rule", "SKL-remote-code-exec"],
        capsys,
    )
    lines = out.splitlines()
    assert len(lines) == 3
    assert all(not line.startswith("[error] SKL-remote-code-exec") for line in lines)


def test_severity_threshold_filters_lower_severity(capsys):
    _, out, _ = _run(["scan", str(E2E), "--format", "text", "--severity", "error"], capsys)
    lines = out.splitlines()
    assert len(lines) == 3
    assert all(line.startswith("[error]") for line in lines)


def test_exit_zero_when_no_findings_at_fail_on(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    # warning only; default fail-on is error → exit 0
    code, _, _ = _run(["scan", str(tmp_path)], capsys)
    assert code == 0
    # lowering fail-on to warning → exit 1
    code, _, _ = _run(["scan", str(tmp_path), "--fail-on", "warning"], capsys)
    assert code == 1


def test_exit_two_on_nonexistent_path(capsys):
    code, _, err = _run(["scan", str(Path("no/such/dir"))], capsys)
    assert code == 2
    assert err != ""


def test_exit_two_on_unknown_rule(capsys):
    code, _, err = _run(["scan", str(E2E), "--rules", "MCP-does-not-exist"], capsys)
    assert code == 2
    assert err != ""


def test_e2e_finding_set_and_byte_identical_across_two_runs(tmp_path):
    out1 = tmp_path / "one.sarif"
    out2 = tmp_path / "two.sarif"

    code1 = _run(["scan", str(E2E), "--output", str(out1)])
    code2 = _run(["scan", str(E2E), "--output", str(out2)])

    assert code1 == 1
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
        ("MCP-shell-unrestricted", "error", "mcp.json", 4),
        ("MCP-allow-all", "error", "mcp.json", 9),
        ("SKL-remote-code-exec", "error", "profiles/alice/skills/evil/SKILL.md", 6),
        ("DEP-unpinned", "warning", "requirements.txt", 1),
    ]
