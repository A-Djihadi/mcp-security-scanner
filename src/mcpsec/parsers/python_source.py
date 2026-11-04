"""Python source parser: one ``python_source`` target per ``.py`` file.

The parser reads the file text (so rules stay pure) and emits a target whose
payload carries the raw ``source`` string for the taint analyzer. A file that
cannot be decoded as UTF-8 is skipped (no target) rather than crashing the scan.
"""

from __future__ import annotations

from pathlib import Path

from ..model import SourceLocation, Target, TargetKind
from ._common import normalize_path


class PythonSourceParser:
    """Parse a ``.py`` file into a single ``python_source`` target."""

    def parse(self, path: Path) -> list[Target]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []
        location = SourceLocation(path=normalize_path(path), start_line=1, start_column=1)
        return [
            Target(
                kind=TargetKind.PYTHON_SOURCE,
                name=normalize_path(path),
                location=location,
                payload={"source": text},
            )
        ]
