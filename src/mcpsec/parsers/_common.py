"""Shared helpers for parsers."""

from __future__ import annotations

from pathlib import Path

from ..model import SourceLocation
from ._json_pos import LineIndex


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
