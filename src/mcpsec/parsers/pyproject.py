"""``pyproject.toml`` parser: PEP 621/508 dependency declarations."""

from __future__ import annotations

import tomllib
from pathlib import Path

from ..errors import ParseError
from ..model import SourceLocation, Target, TargetKind
from ._common import is_pinned_python, normalize_path, split_pep508
from ._json_pos import LineIndex


class PyprojectParser:
    """Parse ``pyproject.toml`` into ``Dependency`` targets.

    Reads ``[project] dependencies`` and ``[project.optional-dependencies]``
    (PEP 621/508). Locations are resolved by scanning for each spec string in
    the raw text (first occurrence — documented limitation, like JSON keys).
    """

    def parse(self, path: Path) -> list[Target]:
        text = path.read_text(encoding="utf-8")
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ParseError(f"invalid TOML in {path}: {exc}") from exc

        index = LineIndex(text)
        targets: list[Target] = []

        project = data.get("project", {}) or {}
        for spec in project.get("dependencies", []) or []:
            targets.append(
                _dependency_target(path, text, index, "project.dependencies", spec)
            )

        for group, specs in (project.get("optional-dependencies", {}) or {}).items():
            for spec in specs or []:
                targets.append(
                    _dependency_target(
                        path, text, index, f"project.optional-dependencies.{group}", spec
                    )
                )

        return targets


def _dependency_target(
    path: Path, text: str, index: LineIndex, section: str, spec: str
) -> Target:
    name, version_spec = split_pep508(spec)
    offset = _locate(text, spec)
    payload = {
        "version_spec": version_spec,
        "manifest": normalize_path(path),
        "pinned": is_pinned_python(version_spec),
        "source": spec,
    }
    line = col = None
    snippet = spec
    if offset is not None:
        line, col = index.line_col(offset)

    location = SourceLocation(
        path=normalize_path(path),
        start_line=line,
        start_column=col,
        snippet=snippet,
    )
    return Target(
        kind=TargetKind.DEPENDENCY,
        name=name,
        location=location,
        payload=payload,
    )


def _locate(text: str, spec: str) -> int | None:
    """Byte offset of the first occurrence of ``spec`` (quoted or bare)."""
    offset = text.find(f'"{spec}"')
    if offset >= 0:
        return offset
    offset = text.find(spec)
    return offset if offset >= 0 else None
