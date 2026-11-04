"""T13 — ``smithery.yaml`` parser and its CLI/discovery wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpsec import cli
from mcpsec.discovery import discover_files
from mcpsec.errors import ParseError
from mcpsec.model import TargetKind
from mcpsec.parsers import SmitheryYamlParser
from mcpsec.rules import build_default_registry
from mcpsec.rules.parsing import MCPParseAmbiguous

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "smithery"


def test_literal_command_function_yields_populated_server():
    targets = SmitheryYamlParser().parse(FIXTURES / "literal" / "smithery.yaml")
    assert len(targets) == 1
    target = targets[0]

    assert target.kind is TargetKind.MCP_SERVER
    assert target.payload["command"] == "node"
    assert target.payload["args"] == ["dist/index.js", "--serve"]
    assert target.payload["env"] == {
        "MY_API_KEY": "literal-key",
        "MY_TOKEN": "literal-token",
    }
    assert target.payload["transport"] == "stdio"
    assert target.payload["parse_ambiguous"] is False


def test_config_schema_required_keys_captured_with_locations():
    targets = SmitheryYamlParser().parse(FIXTURES / "literal" / "smithery.yaml")
    target = targets[0]

    assert target.payload["config_required"] == ["MY_API_KEY", "MY_TOKEN"]
    locs = target.field_locations["config_required"]
    assert set(locs) == {"MY_API_KEY", "MY_TOKEN"}
    assert locs["MY_API_KEY"].start_line == 9
    assert locs["MY_TOKEN"].start_line == 10
    assert locs["MY_API_KEY"].start_column == 7
    assert locs["MY_TOKEN"].start_column == 7


def test_remote_transport_from_non_stdio_type():
    targets = SmitheryYamlParser().parse(FIXTURES / "remote" / "smithery.yaml")
    assert len(targets) == 1
    target = targets[0]

    assert target.payload["transport"] == "remote"
    assert target.payload["start_command_type"] == "streamable-http"
    assert target.payload["command"] is None
    assert target.payload["parse_ambiguous"] is False


def test_dynamic_command_function_yields_command_none_and_ambiguous_flag():
    targets = SmitheryYamlParser().parse(FIXTURES / "dynamic" / "smithery.yaml")
    assert len(targets) == 1
    target = targets[0]

    assert target.payload["command"] is None
    assert target.payload["args"] == []
    assert target.payload["env"] == {}
    assert target.payload["parse_ambiguous"] is True
    assert target.payload["parse_note"]


def test_ambiguous_rule_emits_note_finding():
    targets = SmitheryYamlParser().parse(FIXTURES / "dynamic" / "smithery.yaml")
    findings = MCPParseAmbiguous().check(targets[0])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "MCP-parse-ambiguous"
    assert finding.level == "note"
    assert finding.location.start_line is not None


def test_ambiguous_rule_is_registered_by_default():
    assert "MCP-parse-ambiguous" in build_default_registry()


def test_no_start_command_returns_empty(tmp_path):
    path = tmp_path / "smithery.yaml"
    path.write_text("configSchema:\n  type: object\n", encoding="utf-8")
    assert SmitheryYamlParser().parse(path) == []


def test_malformed_yaml_raises_parse_error(tmp_path):
    path = tmp_path / "smithery.yaml"
    path.write_text("startCommand: [unterminated", encoding="utf-8")
    with pytest.raises(ParseError):
        SmitheryYamlParser().parse(path)


def test_block_body_single_return_is_extracted(tmp_path):
    path = tmp_path / "smithery.yaml"
    path.write_text(
        "startCommand:\n"
        "  type: stdio\n"
        "commandFunction: |-\n"
        "  (config) => { return { command: 'node', args: ['server.js'], env: {} }; }\n",
        encoding="utf-8",
    )
    targets = SmitheryYamlParser().parse(path)
    assert len(targets) == 1
    assert targets[0].payload["command"] == "node"
    assert targets[0].payload["args"] == ["server.js"]
    assert targets[0].payload["env"] == {}
    assert targets[0].payload["parse_ambiguous"] is False


def test_double_quoted_object_literal_is_extracted(tmp_path):
    # The canonical docs example uses double-quoted keys and a multi-line object.
    path = tmp_path / "smithery.yaml"
    path.write_text(
        "startCommand:\n"
        "  type: stdio\n"
        "commandFunction: |-\n"
        '  (config) => ({\n'
        '    "command": "node",\n'
        '    "args": ["dist/index.js"],\n'
        '    "env": {"KEY": "value"}\n'
        "  })\n",
        encoding="utf-8",
    )
    targets = SmitheryYamlParser().parse(path)
    assert len(targets) == 1
    assert targets[0].payload["command"] == "node"
    assert targets[0].payload["args"] == ["dist/index.js"]
    assert targets[0].payload["env"] == {"KEY": "value"}
    assert targets[0].payload["parse_ambiguous"] is False


def test_nested_config_and_command_function_tolerated():
    targets = SmitheryYamlParser().parse(FIXTURES / "nested" / "smithery.yaml")
    assert len(targets) == 1
    target = targets[0]

    assert target.payload["command"] == "uvx"
    assert target.payload["args"] == ["my-server"]
    assert target.payload["env"] == {"DB_PASSWORD": "pw"}
    assert target.payload["config_required"] == ["DB_PASSWORD"]
    assert target.payload["transport"] == "stdio"


def test_discover_files_includes_smithery_yaml(tmp_path):
    (tmp_path / "smithery.yaml").write_text(
        "startCommand:\n  type: stdio\n", encoding="utf-8"
    )
    (tmp_path / "mcp.json").write_text("{}", encoding="utf-8")
    found = discover_files(tmp_path)
    assert [p.name for p in found] == ["mcp.json", "smithery.yaml"]


def test_cli_maps_smithery_yaml_to_parser(tmp_path, capsys):
    (tmp_path / "smithery.yaml").write_text(
        "startCommand:\n"
        "  type: stdio\n"
        "commandFunction: |-\n"
        "  (config) => { if (config.x) { return { command: 'a', args: [], env: {} }; }"
        " return { command: 'b', args: [], env: {} }; }\n",
        encoding="utf-8",
    )
    code = cli.main(["scan", str(tmp_path)])
    # note-level finding; default fail-on is error, so the exit code stays 0.
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    results = doc["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["MCP-parse-ambiguous"]
    assert results[0]["level"] == "note"
