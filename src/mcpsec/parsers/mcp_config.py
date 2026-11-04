"""MCP config parsers (``mcp.json``, ``.mcp.json``, ``claude_desktop_config.json``).

All three share the same JSON shape: a top-level ``mcpServers`` (or ``servers``)
map from server name to a config object with ``command``, ``args``, ``env``,
``cwd``, and optionally ``type``/``url`` for remote servers. The same shape is
reused by ``package.json#mcpServers`` (see ``package_json.py``).
"""

from __future__ import annotations

from pathlib import Path

from ..model import Target, TargetKind
from . import _json_pos
from ._common import location

_REMOTE_TYPES = {
    "http",
    "sse",
    "streamable",
    "streamableHttp",
    "streamable-http",
    "streamable_http",
}


class McpConfigParser:
    """Parse stdio/remote MCP config JSON into ``McpServer`` targets."""

    def parse(self, path: Path) -> list[Target]:
        text = path.read_text(encoding="utf-8")
        root = _json_pos.parse(text)  # raises ParseError on malformed JSON
        index = _json_pos.LineIndex(text)

        servers_node = _find_member(root, "mcpServers") or _find_member(root, "servers")
        if servers_node is None or not isinstance(servers_node.value, dict):
            return []

        return [
            build_server_target(path, index, name, node)
            for name, node in servers_node.members
        ]


class ClaudeDesktopConfigParser(McpConfigParser):
    """Parse ``claude_desktop_config.json`` (stdio transport; same shape)."""


def build_server_target(
    path: Path, index: _json_pos.LineIndex, name: str, node: _json_pos.Node
) -> Target:
    """Build an ``mcp_server`` target from a server-name key and its config node."""
    members = {key: child for key, child in node.members}
    field_locations: dict = {}

    command = _string_or_none(members.get("command"))

    args_node = members.get("args")
    if args_node is not None and isinstance(args_node.value, list):
        args = [item.value for item in args_node.items if isinstance(item.value, str)]
        field_locations["args"] = tuple(
            location(path, index, item.value_offset) for item in args_node.items
        )
    else:
        args = []

    env_node = members.get("env")
    if env_node is not None and isinstance(env_node.value, dict):
        env = {
            key: value
            for key, value in env_node.value.items()
            if isinstance(value, str)
        }
        field_locations["env"] = {
            key: location(path, index, child.value_offset)
            for key, child in env_node.members
        }
    else:
        env = {}

    headers_node = members.get("headers")
    if headers_node is not None and isinstance(headers_node.value, dict):
        headers: dict[str, str] = {}
        header_locs: dict[str, object] = {}
        for key, child in headers_node.members:
            if isinstance(child.value, str):
                headers[key] = child.value
                header_locs[key] = location(path, index, child.value_offset)
        field_locations["headers"] = header_locs
    else:
        headers = {}

    cwd = _string_or_none(members.get("cwd"))
    url = _string_or_none(members.get("url"))
    mcp_type = _string_or_none(members.get("type"))

    transport = "remote" if (url is not None or mcp_type in _REMOTE_TYPES) else "stdio"

    if command is not None:
        field_locations["command"] = location(
            path, index, members["command"].value_offset
        )
    if cwd is not None:
        field_locations["cwd"] = location(path, index, members["cwd"].value_offset)
    if url is not None:
        field_locations["url"] = location(path, index, members["url"].value_offset)

    payload = {
        "command": command,
        "args": args,
        "env": env,
        "cwd": cwd,
        "transport": transport,
        "url": url,
        "type": mcp_type,
        "headers": headers,
    }

    return Target(
        kind=TargetKind.MCP_SERVER,
        name=name,
        location=location(path, index, node.key_offset, snippet=name),
        payload=payload,
        field_locations=field_locations,
    )


def _find_member(node: _json_pos.Node, key: str) -> _json_pos.Node | None:
    for member_key, child in node.members:
        if member_key == key:
            return child
    return None


def _string_or_none(node: _json_pos.Node | None) -> str | None:
    if node is not None and isinstance(node.value, str):
        return node.value
    return None
