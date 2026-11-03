"""``SKILL.md`` parser: YAML frontmatter + line-indexed markdown body."""

from __future__ import annotations

from pathlib import Path

import yaml

from ..errors import ParseError
from ..model import SourceLocation, Target, TargetKind
from ._common import normalize_path


class SkillMarkdownParser:
    """Parse a ``SKILL.md`` into a single ``Skill`` target.

    Frontmatter is YAML between ``---`` delimiters; unknown keys are tolerated.
    The body is line-indexed so rules can point at the exact offending line.
    """

    def parse(self, path: Path) -> list[Target]:
        text = path.read_text(encoding="utf-8")
        frontmatter, body, body_start_line = _split_frontmatter(text)

        body_lines = body.splitlines()
        normalized = normalize_path(path)
        field_locations = {
            "body": tuple(
                SourceLocation(
                    path=normalized,
                    start_line=body_start_line + i,
                    start_column=1,
                    snippet=line,
                )
                for i, line in enumerate(body_lines)
            )
        }

        name = frontmatter.get("name") if isinstance(frontmatter.get("name"), str) else None
        name = name or path.parent.name

        payload = {
            "frontmatter": frontmatter,
            "body": body,
            "body_lines": body_lines,
        }

        return [
            Target(
                kind=TargetKind.SKILL,
                name=name,
                location=SourceLocation(path=normalized, start_line=1, start_column=1),
                payload=payload,
                field_locations=field_locations,
            )
        ]


def _split_frontmatter(text: str) -> tuple[dict, str, int]:
    """Return (frontmatter, body, 1-based line of the first body line)."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text, 1

    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            end = i
            break
    if end is None:
        raise ParseError("unterminated YAML frontmatter")

    try:
        frontmatter = yaml.safe_load("\n".join(lines[1:end]))
    except yaml.YAMLError as exc:
        raise ParseError(f"invalid YAML frontmatter: {exc}") from exc

    if not isinstance(frontmatter, dict):
        frontmatter = {}

    body = "\n".join(lines[end + 1 :])
    return frontmatter, body, end + 2
