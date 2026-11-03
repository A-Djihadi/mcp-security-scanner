"""``package.json`` parser: ``mcpServers`` field + ``dependencies``/``devDependencies``."""

from __future__ import annotations

from pathlib import Path

from ..model import Target, TargetKind
from . import _json_pos
from ._common import is_pinned_npm, location, normalize_path, raw_line
from .mcp_config import build_server_target


class PackageJsonParser:
    """Parse ``package.json`` into ``McpServer`` and ``Dependency`` targets.

    The ``mcpServers`` field (same shape as ``mcp.json``) yields servers; the
    ``dependencies``/``devDependencies`` maps yield dependencies.
    """

    def parse(self, path: Path) -> list[Target]:
        text = path.read_text(encoding="utf-8")
        root = _json_pos.parse(text)
        index = _json_pos.LineIndex(text)
        targets: list[Target] = []

        mcp_node = _find_member(root, "mcpServers")
        if mcp_node is not None and isinstance(mcp_node.value, dict):
            for name, node in mcp_node.members:
                targets.append(build_server_target(path, index, name, node))

        for section in ("dependencies", "devDependencies"):
            deps_node = _find_member(root, section)
            if deps_node is not None and isinstance(deps_node.value, dict):
                for name, node in deps_node.members:
                    targets.append(
                        _dependency_target(path, text, index, section, name, node)
                    )

        return targets


def _dependency_target(
    path: Path,
    text: str,
    index: _json_pos.LineIndex,
    section: str,
    name: str,
    node: _json_pos.Node,
) -> Target:
    spec = node.value if isinstance(node.value, str) else ""
    payload = {
        "version_spec": spec,
        "manifest": normalize_path(path),
        "pinned": is_pinned_npm(spec),
        "source": raw_line(text, node.key_offset if node.key_offset is not None else 0),
    }
    return Target(
        kind=TargetKind.DEPENDENCY,
        name=name,
        location=location(path, index, node.key_offset, snippet=name),
        payload=payload,
    )


def _find_member(node: _json_pos.Node, key: str) -> _json_pos.Node | None:
    for member_key, child in node.members:
        if member_key == key:
            return child
    return None
