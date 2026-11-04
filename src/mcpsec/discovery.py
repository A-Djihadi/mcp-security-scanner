"""File discovery.

Discovers every supported input format under a scan root. T5 added the Hermes
skill layout (``profiles/*/skills/*/SKILL.md``); the CLI (T10) walks all
supported filenames recursively and maps each to its parser. T22 adds ``*.py``
source files for the taint/flow analysis, and therefore also excludes
never-source directories (vendored dependencies and caches) so a Python server
tree does not scan its own ``.venv``.
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

_PYTHON_SUFFIX = ".py"

# Directories that are never part of an MCP server's own source tree. Keeping
# these out of discovery prevents scanning vendored dependencies and caches.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".egg-info",
        "node_modules",
        "dist",
        "build",
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
    Hermes layout is a subset of the recursive walk) and any ``*.py`` source
    file (taint/flow analysis, T22). Files under ``_SKIP_DIRS`` are excluded.
    """
    root = Path(root)
    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in _SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if path.name in _SUPPORTED_NAMES or path.name.endswith(_PYTHON_SUFFIX):
            found.append(path.relative_to(root))
    return sorted(found, key=lambda p: p.as_posix())
