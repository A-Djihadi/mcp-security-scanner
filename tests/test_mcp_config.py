"""T3 — MCP config parsers (mcp.json, .mcp.json, claude_desktop_config.json)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpsec.errors import ParseError
from mcpsec.model import TargetKind
from mcpsec.parsers import ClaudeDesktopConfigParser, McpConfigParser

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_mcp_json_yields_one_server_per_key_with_fields():
    targets = McpConfigParser().parse(FIXTURES / "mcp.json")
    assert [t.name for t in targets] == ["filesystem", "remote-thing"]

    fs = next(t for t in targets if t.name == "filesystem")
    assert fs.kind is TargetKind.MCP_SERVER
    assert fs.payload["command"] == "npx"
    assert fs.payload["args"] == [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/tmp",
    ]
    assert fs.payload["env"] == {"ROOT": "/tmp"}
    assert fs.payload["cwd"] == "/workspace"
    assert fs.payload["transport"] == "stdio"
    assert fs.payload["url"] is None


def test_command_source_location_is_exact(tmp_path):
    targets = McpConfigParser().parse(FIXTURES / "mcp.json")
    fs = next(t for t in targets if t.name == "filesystem")
    command_loc = fs.field_locations["command"]
    assert (command_loc.start_line, command_loc.start_column) == (4, 18)

    # args elements carry their own locations, parallel to the args list
    arg_locs = fs.field_locations["args"]
    assert len(arg_locs) == 3
    assert (arg_locs[0].start_line, arg_locs[0].start_column) == (5, 16)


def test_dot_mcp_json_parses_to_same_model():
    targets = McpConfigParser().parse(FIXTURES / ".mcp.json")
    assert [t.name for t in targets] == ["gh-committer"]
    server = targets[0]
    assert server.payload["command"] == "node"
    assert server.payload["args"] == ["dist/index.js", "--token", "$GITHUB_TOKEN"]
    assert (server.field_locations["command"].start_line,
            server.field_locations["command"].start_column) == (4, 18)


def test_claude_desktop_config_parses_to_same_model():
    targets = ClaudeDesktopConfigParser().parse(FIXTURES / "claude_desktop_config.json")
    assert [t.name for t in targets] == ["git"]
    server = targets[0]
    assert server.payload["command"] == "uvx"
    assert server.payload["args"] == ["mcp-server-git"]
    assert server.payload["env"] == {
        "GIT_SSH_COMMAND": "ssh -i /home/user/.ssh/id_ed25519"
    }
    assert server.payload["transport"] == "stdio"


def test_remote_server_detected_from_url():
    targets = McpConfigParser().parse(FIXTURES / "mcp.json")
    remote = next(t for t in targets if t.name == "remote-thing")
    assert remote.payload["transport"] == "remote"
    assert remote.payload["url"] == "https://example.com/mcp"
    assert remote.payload["command"] is None


def test_no_mcp_servers_key_returns_empty(tmp_path):
    path = tmp_path / "other.json"
    path.write_text('{"someOtherKey": {"command": "true"}}', encoding="utf-8")
    assert McpConfigParser().parse(path) == []


def test_servers_variant_is_supported(tmp_path):
    path = tmp_path / "servers.json"
    path.write_text(
        '{"servers": {"srv": {"command": "echo", "args": ["hi"]}}}',
        encoding="utf-8",
    )
    targets = McpConfigParser().parse(path)
    assert [t.name for t in targets] == ["srv"]
    assert targets[0].payload["command"] == "echo"


def test_malformed_json_raises_parse_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text('{"mcpServers": {"srv": {"command": ', encoding="utf-8")
    with pytest.raises(ParseError):
        McpConfigParser().parse(path)
