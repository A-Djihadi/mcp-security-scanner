"""Positional JSON scanner.

Python's ``json`` module discards source positions, but rules must point at the
offending line/column. This module parses JSON while recording the byte offset
of every object key and value token, then maps offsets to 1-based line/column
via a precomputed line-offset index (ADR-0003).

Repeated object keys resolve to the first occurrence (documented, tested).
"""

from __future__ import annotations

import bisect
import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..errors import ParseError

_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")


@dataclass
class Node:
    """A parsed JSON value with the byte offsets of its key and value tokens."""

    value: Any
    key_offset: int | None = None
    value_offset: int | None = None
    members: list[tuple[str, Node]] = field(default_factory=list)
    items: list[Node] = field(default_factory=list)


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    return i


def _read_string(text: str, i: int) -> tuple[str, int]:
    j = i + 1
    while True:
        if j >= len(text):
            raise ParseError("unterminated string in JSON")
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == '"':
            break
        j += 1
    return json.loads(text[i : j + 1]), j + 1


def _parse_value(text: str, i: int) -> tuple[Node, int]:
    i = _skip_ws(text, i)
    if i >= len(text):
        raise ParseError("unexpected end of JSON input")
    ch = text[i]
    if ch == '"':
        value, end = _read_string(text, i)
        return Node(value=value, value_offset=i), end
    if ch == "{":
        return _parse_object(text, i)
    if ch == "[":
        return _parse_array(text, i)
    for literal, value in (("true", True), ("false", False), ("null", None)):
        if text.startswith(literal, i):
            return Node(value=value, value_offset=i), i + len(literal)
    match = _NUMBER.match(text, i)
    if match is None:
        raise ParseError(f"invalid JSON token at byte offset {i}")
    return Node(value=json.loads(match.group()), value_offset=i), match.end()


def _parse_object(text: str, i: int) -> tuple[Node, int]:
    start = i
    i = _skip_ws(text, i + 1)
    members: list[tuple[str, Node]] = []
    value: dict[str, Any] = {}
    if i < len(text) and text[i] == "}":
        return Node(value=value, value_offset=start, members=members), i + 1
    while True:
        i = _skip_ws(text, i)
        if i >= len(text) or text[i] != '"':
            raise ParseError("expected a string key in JSON object")
        key, key_end = _read_string(text, i)
        key_offset = i
        i = _skip_ws(text, key_end)
        if i >= len(text) or text[i] != ":":
            raise ParseError("expected ':' after JSON object key")
        child, i = _parse_value(text, i + 1)
        child.key_offset = key_offset
        members.append((key, child))
        value[key] = child.value
        i = _skip_ws(text, i)
        if i >= len(text):
            raise ParseError("unterminated JSON object")
        if text[i] == ",":
            i += 1
            continue
        if text[i] == "}":
            return Node(value=value, value_offset=start, members=members), i + 1
        raise ParseError("expected ',' or '}' in JSON object")


def _parse_array(text: str, i: int) -> tuple[Node, int]:
    start = i
    i = _skip_ws(text, i + 1)
    items: list[Node] = []
    value: list[Any] = []
    if i < len(text) and text[i] == "]":
        return Node(value=value, value_offset=start, items=items), i + 1
    while True:
        child, i = _parse_value(text, i)
        items.append(child)
        value.append(child.value)
        i = _skip_ws(text, i)
        if i >= len(text):
            raise ParseError("unterminated JSON array")
        if text[i] == ",":
            i += 1
            continue
        if text[i] == "]":
            return Node(value=value, value_offset=start, items=items), i + 1
        raise ParseError("expected ',' or ']' in JSON array")


def parse(text: str) -> Node:
    """Parse ``text`` into a value tree with byte offsets, or raise ParseError."""
    i = _skip_ws(text, 0)
    root, end = _parse_value(text, i)
    end = _skip_ws(text, end)
    if end != len(text):
        raise ParseError("trailing data after JSON value")
    return root


class LineIndex:
    """Maps a byte offset to a 1-based (line, column) pair."""

    def __init__(self, text: str) -> None:
        self._starts = [0]
        for idx, ch in enumerate(text):
            if ch == "\n":
                self._starts.append(idx + 1)

    def line_col(self, offset: int) -> tuple[int, int]:
        line_idx = bisect.bisect_right(self._starts, offset) - 1
        return line_idx + 1, offset - self._starts[line_idx] + 1
