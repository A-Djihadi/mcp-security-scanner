"""T5 — SKILL.md parser & Hermes profiles/*/skills/*/ discovery."""

from __future__ import annotations

from pathlib import Path

from mcpsec.discovery import discover_skill_files
from mcpsec.model import TargetKind
from mcpsec.parsers import SkillMarkdownParser

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_skill_md_yields_one_skill_with_frontmatter_and_body():
    targets = SkillMarkdownParser().parse(FIXTURES / "skill_basic" / "SKILL.md")
    assert len(targets) == 1
    skill = targets[0]
    assert skill.kind is TargetKind.SKILL
    assert skill.name == "hello"
    assert skill.payload["frontmatter"] == {
        "name": "hello",
        "description": "A test skill",
    }
    assert skill.payload["body"].startswith("# Hello skill")
    assert skill.payload["body_lines"][0] == "# Hello skill"


def test_body_line_locations_match_physical_lines():
    skill = SkillMarkdownParser().parse(FIXTURES / "skill_basic" / "SKILL.md")[0]
    body_locs = skill.field_locations["body"]
    lines = skill.payload["body_lines"]
    assert len(body_locs) == len(lines)

    # "# Hello skill" is physical line 5, "Line two of the body." is line 7.
    assert body_locs[0].start_line == 5
    assert body_locs[2].start_line == 7
    assert lines[2] == "Line two of the body."

    for loc, expected_line in zip(body_locs, (5, 6, 7, 8, 9)):
        assert loc.start_line == expected_line


def test_unknown_frontmatter_keys_are_tolerated():
    skill = SkillMarkdownParser().parse(FIXTURES / "skill_unknown_keys" / "SKILL.md")[0]
    fm = skill.payload["frontmatter"]
    assert fm["name"] == "unknown"
    assert fm["custom_field"] == "tolerated"
    assert fm["nested"] == ["list", "of", "things"]


def test_skill_without_frontmatter_still_yields_skill():
    skill = SkillMarkdownParser().parse(
        FIXTURES / "skill_no_frontmatter" / "SKILL.md"
    )[0]
    assert skill.payload["frontmatter"] == {}
    assert skill.payload["body"].startswith("# A skill with no frontmatter")
    assert skill.payload["body_lines"][0] == "# A skill with no frontmatter"
    assert skill.payload["body_lines"][-1] == "The whole file is the body."


def test_discovery_finds_hermes_layout_skills(tmp_path):
    root = tmp_path
    (root / "profiles" / "alice" / "skills" / "one").mkdir(parents=True)
    (root / "profiles" / "alice" / "skills" / "one" / "SKILL.md").write_text(
        "---\nname: one\n---\n", encoding="utf-8"
    )
    (root / "profiles" / "bob" / "skills" / "two").mkdir(parents=True)
    (root / "profiles" / "bob" / "skills" / "two" / "SKILL.md").write_text(
        "---\nname: two\n---\n", encoding="utf-8"
    )
    # a stray SKILL.md outside the Hermes layout must not be matched
    (root / "random").mkdir(parents=True)
    (root / "random" / "SKILL.md").write_text("not a skill\n", encoding="utf-8")

    found = discover_skill_files(root)
    parents = sorted(p.relative_to(root).as_posix() for p in found)
    assert parents == [
        "profiles/alice/skills/one/SKILL.md",
        "profiles/bob/skills/two/SKILL.md",
    ]


def test_discovery_returns_empty_for_no_matches(tmp_path):
    assert discover_skill_files(tmp_path) == []
