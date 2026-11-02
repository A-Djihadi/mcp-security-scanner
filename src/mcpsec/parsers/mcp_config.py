"""MCP config parsers (``mcp.json``, ``.mcp.json``, ``claude_desktop_config.json``).

All three share the same JSON shape: a top-level ``mcpServers`` (or ``servers``)
map from server name to a config object with ``command``, ``args``, ``env``,
``cwd``, and optionally ``type``/``url`` for remote servers.
"""

from __future__ import annotations

from pathlib import Path

from ..model import SourceLocation, Target, TargetKind
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
            self._server_target(path, index, name, node)
            for name, node in servers_node.members
        ]

    def _server_target(
        self, path: Path, index: _json_pos.LineIndex, name: str, node: _json_pos.Node
    ) -> Target:
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

        cwd = _string_or_none(members.get("cwd"))
        url = _string_or_none(members.get("url"))
        mcp_type = _string_or_none(members.get("type"))

        transport = "remote" if (url is not None or mcp_type in _REMOTE_TYPES) else "stdio"

        if command is not None:
            field_locations["command"] = location(path, index, members["command"].value_offset)
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
        }

        return Target(
            kind=TargetKind.MCP_SERVER,
            name=name,
            location=location(path, index, node.key_offset, snippet=name),
            payload=payload,
            field_locations=field_locations,
        )


class ClaudeDesktopConfigParser(McpConfigParser):
    """Parse ``claude_desktop_config.json`` (stdio transport; same shape)."""


def _find_member(node: _json_pos.Node, key: str) -> _json_pos.Node | None:
    for member_key, child in node.members:
        if member_key == key:
            return child
    return None


def _string_or_none(node: _json_pos.Node | None) -> str | None:
    if node is not None and isinstance(node.value, str):
        return node.value
    return None
