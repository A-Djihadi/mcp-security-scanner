"""File discovery.

T5 implements the Hermes skill layout (``profiles/*/skills/*/SKILL.md``). The
full discovery of every supported input format lands with the CLI (T10).
"""

from __future__ import annotations

from pathlib import Path


def discover_skill_files(root: Path) -> list[Path]:
    """Find ``SKILL.md`` files under the Hermes ``profiles/*/skills/*/`` layout.

    Results are sorted for determinism.
    """
    return sorted(root.glob("profiles/*/skills/*/SKILL.md"))
