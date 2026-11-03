"""Exception types shared across mcpsec."""

from __future__ import annotations


class McpsecError(Exception):
    """Base class for all mcpsec errors."""


class ParseError(McpsecError):
    """A file could not be parsed into targets (malformed or unreadable input).

    The scan CLI turns this into a single, actionable error finding; parsers
    never let a malformed input crash the process with a bare traceback.
    """
