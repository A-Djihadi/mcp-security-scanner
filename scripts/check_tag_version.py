"""Tag↔version consistency check for the release workflow.

Usage:
    python scripts/check_tag_version.py <tag>

Reads ``[project].version`` from the repository's ``pyproject.toml`` and
compares it to the git tag (a leading ``v`` is stripped). Exits 0 when they
match, 1 on mismatch, 2 on a usage error — each with a clear message.

The pure comparison lives in :func:`verify_tag_version` so it can be unit
tested without shelling out or reading the filesystem.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


def verify_tag_version(tag: str, version: str) -> bool:
    """Return ``True`` when ``tag`` (with a leading ``v`` stripped) equals ``version``."""
    normalized = tag[1:] if tag.startswith("v") else tag
    return normalized == version


def read_project_version(pyproject: Path) -> str:
    """Return the ``[project].version`` string from a ``pyproject.toml`` file."""
    with pyproject.open("rb") as fh:
        data = tomllib.load(fh)
    return data["project"]["version"]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: check_tag_version.py <tag>", file=sys.stderr)
        return 2

    tag = args[0]
    root = Path(__file__).resolve().parent.parent
    version = read_project_version(root / "pyproject.toml")

    if verify_tag_version(tag, version):
        print(f"tag {tag!r} matches project version {version!r}")
        return 0

    print(
        f"tag {tag!r} does not match project version {version!r} "
        f"(expected {version!r})",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
