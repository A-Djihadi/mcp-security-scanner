"""Data-source providers — the only layer that performs network I/O.

Online rules receive a provider here at construction and stay I/O-free in
``check()`` (ADR-0007). Everything is stdlib-only (``urllib``); the base install
remains PyYAML-only.
"""

from __future__ import annotations

from ._http import DEFAULT_ATTEMPTS, DEFAULT_TIMEOUT, DataUnavailable
from .providers import (
    NpmProvider,
    OSVProvider,
    PopularPackagesProvider,
    PyPIProvider,
    ReachabilityProvider,
)

__all__ = [
    "DEFAULT_ATTEMPTS",
    "DEFAULT_TIMEOUT",
    "DataUnavailable",
    "NpmProvider",
    "OSVProvider",
    "PopularPackagesProvider",
    "PyPIProvider",
    "ReachabilityProvider",
]
