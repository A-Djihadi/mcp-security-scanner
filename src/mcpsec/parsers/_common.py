"""Shared helpers for parsers."""

from __future__ import annotations

import re
from pathlib import Path

from ..model import SourceLocation
from ._json_pos import LineIndex

# A PEP 508 requirement: name [extras] version-spec [; marker]
_PEP508 = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<spec>[^;]*)(?P<marker>;.*)?$"
)

# An exact npm/semver version: 1, 1.2, 1.2.3 with optional pre-release/build.
_SEMVER = re.compile(r"^\d+(\.\d+){0,2}([-+][0-9A-Za-z.-]+)?$")


def normalize_path(path: Path) -> str:
    """Return a URI-safe, forward-slash path string (relative to scan root)."""
    return str(path).replace("\\", "/")


def location(
    path: Path, index: LineIndex, offset: int | None, snippet: str | None = None
) -> SourceLocation:
    if offset is None:
        return SourceLocation(path=normalize_path(path), snippet=snippet)
    line, col = index.line_col(offset)
    return SourceLocation(
        path=normalize_path(path), start_line=line, start_column=col, snippet=snippet
    )


def raw_line(text: str, offset: int) -> str:
    """Return the stripped physical line containing ``offset``."""
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return text[start:end].strip()


def split_pep508(requirement: str) -> tuple[str, str]:
    """Split a PEP 508 requirement into (name, version_spec).

    ``version_spec`` is the version-specifier portion only (markers excluded),
    so it is safe to test for ``==`` / ``===`` pins without false positives
    from ``; python_version == '...'`` markers.
    """
    match = _PEP508.match(requirement)
    if match is None:
        return requirement.strip(), ""
    return match.group("name"), match.group("spec").strip()


def is_pinned_python(version_spec: str) -> bool:
    """PEP 508 spec is pinned iff it uses ``==`` or ``===``."""
    return "==" in version_spec


def is_pinned_npm(version_spec: str) -> bool:
    """npm spec is pinned iff it is an exact semver (no range/wildcard/URL)."""
    return bool(_SEMVER.match(version_spec.strip()))
