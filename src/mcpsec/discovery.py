"""File discovery.

Discovers every supported input format under a scan root. T5 added the Hermes
skill layout (``profiles/*/skills/*/SKILL.md``); the CLI (T10) walks all
supported filenames recursively and maps each to its parser.
"""

from __future__ import annotations

from pathlib import Path

_SUPPORTED_NAMES = frozenset(
    {
        "mcp.json",
        ".mcp.json",
        "claude_desktop_config.json",
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "SKILL.md",
        "smithery.yaml",
    }
)


def discover_skill_files(root: Path) -> list[Path]:
    """Find ``SKILL.md`` files under the Hermes ``profiles/*/skills/*/`` layout.

    Results are sorted for determinism.
    """
    return sorted(root.glob("profiles/*/skills/*/SKILL.md"))


def discover_files(root: Path) -> list[Path]:
    """Return supported input files under ``root`` as paths relative to it.

    Sorted by relative path for determinism. Includes any ``SKILL.md`` (the
    Hermes layout is a subset of the recursive walk).
    """
    root = Path(root)
    found: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and path.name in _SUPPORTED_NAMES:
            found.append(path.relative_to(root))
    return sorted(found, key=lambda p: p.as_posix())
