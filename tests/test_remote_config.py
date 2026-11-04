"""T14 — remote MCP parser: ``headers``, ``type``, ``url``, resolved ``transport``.

The parser captures the remote-server fields for ``mcp.json`` /
``.mcp.json`` / ``claude_desktop_config.json`` / ``package.json#mcpServers``.
Each ``headers`` entry carries a per-header ``SourceLocation`` so rules can point
at the exact offending header. Remote entry = ``transport == "remote"``.
"""

from __future__ import annotations

from pathlib import Path

from mcpsec.parsers import (
    ClaudeDesktopConfigParser,
    McpConfigParser,
    PackageJsonParser,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _by_name(targets, name):
    return next(t for t in targets if t.name == name)


def test_remote_entry_yields_remote_transport_and_url_location():
    targets = McpConfigParser().parse(FIXTURES / "mcp_remote.json")
    remote = _by_name(targets, "remote-sse")
    assert remote.payload["transport"] == "remote"
    assert remote.payload["url"] == "https://example.com/mcp"
    assert remote.payload["type"] == "sse"

    url_loc = remote.field_locations["url"]
    assert url_loc.start_line == 5
    assert url_loc.start_column == 14


def test_headers_parse_to_dict_with_per_header_locations():
    targets = McpConfigParser().parse(FIXTURES / "mcp_remote.json")
    remote = _by_name(targets, "remote-sse")

    assert remote.payload["headers"] == {
        "Authorization": "Bearer sk-abcdef123456",
        "Content-Type": "application/json",
    }

    header_locs = remote.field_locations["headers"]
    assert set(header_locs) == {"Authorization", "Content-Type"}

    auth_loc = header_locs["Authorization"]
    assert auth_loc.start_line == 7
    assert auth_loc.start_column == 26

    content_type_loc = header_locs["Content-Type"]
    assert content_type_loc.start_line == 8
    assert content_type_loc.start_column == 25


def test_package_json_remote_entry_same_shape(tmp_path):
    path = tmp_path / "package.json"
    path.write_text(
        '{"mcpServers": {"remote": {"type": "sse", "url": "https://x/mcp",'
        ' "headers": {"X-API-Key": "sk-123"}}}}',
        encoding="utf-8",
    )
    targets = PackageJsonParser().parse(path)
    servers = [t for t in targets if t.kind.value == "mcp_server"]
    assert [t.name for t in servers] == ["remote"]
    remote = servers[0]
    assert remote.payload["transport"] == "remote"
    assert remote.payload["url"] == "https://x/mcp"
    assert remote.payload["type"] == "sse"
    assert remote.payload["headers"] == {"X-API-Key": "sk-123"}
    assert "X-API-Key" in remote.field_locations["headers"]


def test_claude_desktop_remote_entry_same_shape(tmp_path):
    path = tmp_path / "claude_desktop_config.json"
    path.write_text(
        '{"mcpServers": {"remote": {"type": "streamable-http",'
        ' "url": "https://x/mcp", "headers": {"Authorization": "Bearer t"}}}}',
        encoding="utf-8",
    )
    targets = ClaudeDesktopConfigParser().parse(path)
    remote = targets[0]
    assert remote.payload["transport"] == "remote"
    assert remote.payload["url"] == "https://x/mcp"
    assert remote.payload["type"] == "streamable-http"
    assert remote.payload["headers"] == {"Authorization": "Bearer t"}


def test_remote_type_without_url_yields_remote_and_none_url():
    targets = McpConfigParser().parse(FIXTURES / "mcp_remote.json")
    remote = _by_name(targets, "remote-type-only")
    assert remote.payload["transport"] == "remote"
    assert remote.payload["url"] is None
    assert remote.payload["type"] == "streamable-http"
    assert remote.payload["headers"] == {}


def test_stdio_entry_is_unchanged():
    targets = McpConfigParser().parse(FIXTURES / "mcp_remote.json")
    local = _by_name(targets, "local-tool")
    assert local.payload["transport"] == "stdio"
    assert local.payload["url"] is None
    assert local.payload["type"] is None
    assert local.payload["headers"] == {}
    assert local.payload["command"] == "node"
    assert local.payload["args"] == ["server.js"]
