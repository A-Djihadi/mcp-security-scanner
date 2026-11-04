"""Data-source providers: OSV.dev, PyPI, npm, and a reachability probe.

Each provider wraps a shared, memoized, bounded HTTP client and exposes a small,
domain-specific method. Providers are injected into online rules at construction,
so a rule's ``check()`` stays I/O-free and deterministic over
``(target, provider-output)`` (ADR-0007). All endpoint shapes and rate limits are
marked "to verify" and pinned by the test fixtures in ``tests/``.
"""

from __future__ import annotations

from urllib.parse import quote

from ._http import (
    DEFAULT_ATTEMPTS,
    DEFAULT_TIMEOUT,
    DataUnavailable,
    _HttpClient,
)

# Endpoints — exact host/paths are "to verify" against the live services.
OSV_BASE = "https://api.osv.dev"  # to verify
PYPI_JSON_BASE = "https://pypi.org/pypi"  # PyPI JSON API — to verify
NPM_REGISTRY = "https://registry.npmjs.org"  # npm registry — to verify


class PyPIProvider:
    """Latest version from the PyPI JSON API (``/pypi/<name>/json``)."""

    def __init__(
        self,
        *,
        client: _HttpClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_ATTEMPTS,
    ) -> None:
        self._client = client or _HttpClient(
            timeout=timeout, max_attempts=max_attempts
        )

    def latest_version(self, name: str) -> str | None:
        """Return the latest version, or ``None`` when the package is unknown (404)."""
        data = self._client.get_json(f"{PYPI_JSON_BASE}/{quote(name)}/json")
        if data is None:
            return None
        info = data.get("info") if isinstance(data, dict) else {}
        version = info.get("version")  # to verify: latest-version field
        return version if isinstance(version, str) else None


class NpmProvider:
    """Latest version from the npm registry (``/<name>``, ``dist-tags.latest``)."""

    def __init__(
        self,
        *,
        client: _HttpClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_ATTEMPTS,
    ) -> None:
        self._client = client or _HttpClient(
            timeout=timeout, max_attempts=max_attempts
        )

    def latest_version(self, name: str) -> str | None:
        """Return the latest version, or ``None`` when the package is unknown (404)."""
        # Scoped names (``@scope/pkg``) encode their ``/`` as ``%2F`` — to verify.
        data = self._client.get_json(f"{NPM_REGISTRY}/{quote(name, safe='@')}")
        if data is None:
            return None
        dist_tags = data.get("dist-tags") if isinstance(data, dict) else {}
        latest = dist_tags.get("latest")  # to verify: latest-version field
        return latest if isinstance(latest, str) else None


class OSVProvider:
    """OSV.dev vulnerability queries (batch + full record)."""

    def __init__(
        self,
        *,
        client: _HttpClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_ATTEMPTS,
    ) -> None:
        self._client = client or _HttpClient(
            timeout=timeout, max_attempts=max_attempts
        )

    def query_batch(self, queries: list[dict]) -> dict:
        """``POST /v1/querybatch`` with ``{"queries": [...]}``.

        The exact request/response shape (input order, ``next_page_token``
        pagination) is "to verify"; the provider returns the parsed JSON for the
        rule to interpret.
        """
        data = self._client.post_json(
            f"{OSV_BASE}/v1/querybatch", {"queries": queries}
        )
        if data is None:
            raise DataUnavailable("OSV.dev querybatch returned no data", kind="http")
        if not isinstance(data, dict):
            raise DataUnavailable(
                "OSV.dev querybatch returned malformed data", kind="malformed"
            )
        return data

    def query_vulns(self, queries: list[dict]) -> list[dict]:
        """Return every vuln summary for ``queries``, following pagination.

        Query/response shape pinned from the OSV.dev docs (to verify): each query
        is ``{"package": {"name", "ecosystem"}, "version"}`` and a response is
        ``{"results": [{"vulns": [{"id", "modified"}], "next_page_token"}]}`` in
        input order. When a result carries ``next_page_token``, the same query is
        re-sent with ``page_token`` set; queries without a token are dropped from
        the follow-up request. See the fixtures in ``tests/``.
        """
        summaries: list[dict] = []
        active = list(queries)
        while active:
            data = self.query_batch(active)
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list):
                raise DataUnavailable(
                    "OSV.dev querybatch missing results", kind="malformed"
                )
            next_queries: list[dict] = []
            for query, result in zip(active, results):
                if not isinstance(result, dict):
                    continue
                vulns = result.get("vulns")
                if isinstance(vulns, list):
                    summaries.extend(v for v in vulns if isinstance(v, dict))
                token = result.get("next_page_token")
                if token:
                    next_queries.append({**query, "page_token": token})
            active = next_queries
        return summaries

    def get_vuln(self, vuln_id: str) -> dict | None:
        """``GET /v1/vulns/{id}``; ``None`` on 404, ``DataUnavailable`` otherwise."""
        data = self._client.get_json(f"{OSV_BASE}/v1/vulns/{quote(vuln_id)}")
        if data is None:
            return None
        if not isinstance(data, dict):
            raise DataUnavailable(
                f"OSV.dev vuln record for {vuln_id} is malformed", kind="malformed"
            )
        return data


class ReachabilityProvider:
    """HTTP/SSE reachability probe for remote MCP server URLs.

    The exact SSE handshake for streamable endpoints is "to verify"; this
    implementation performs a bounded HTTP GET and treats any response (including
    404) as the endpoint being reachable.
    """

    def __init__(
        self,
        *,
        client: _HttpClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_ATTEMPTS,
    ) -> None:
        self._client = client or _HttpClient(
            timeout=timeout, max_attempts=max_attempts
        )

    def probe(self, url: str) -> str:
        """Return ``"reachable"`` or ``"unreachable"``.

        A connection refusal is a definite ``"unreachable"``; any other failure
        (timeout, DNS, malformed URL) raises ``DataUnavailable`` because the
        outcome cannot be determined.
        """
        try:
            self._client.get(url)
            return "reachable"
        except DataUnavailable as exc:
            if exc.kind == "refused":
                return "unreachable"
            raise


class PopularPackagesProvider:
    """Popularity-ranked package-name seed list for typosquat detection.

    The seed-list source (PyPI "top N" download ranking, npm "top N", or a
    curated allowlist) is an owner decision and is "to verify" for a licenseable,
    offline-cacheable source (ADR-0007). This placeholder returns a small bundled
    list so the rule is runnable; a real source must replace ``_DEFAULT_SEED``.
    """

    def __init__(
        self,
        *,
        client: _HttpClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_ATTEMPTS,
    ) -> None:
        self._client = client or _HttpClient(
            timeout=timeout, max_attempts=max_attempts
        )

    def popular_packages(self) -> list[str]:
        """Return the popularity-ranked seed list.

        The default source is a bundled placeholder ("to verify"); the contract
        is a ``list[str]`` in descending popularity order, injected into the
        ``DEP-unknown`` rule so the rule stays pure.
        """
        return list(_DEFAULT_SEED)


# Placeholder seed list — to verify against a licenseable source (ADR-0007).
_DEFAULT_SEED: list[str] = [
    "requests",
    "flask",
    "numpy",
    "django",
    "pandas",
    "express",
    "react",
    "lodash",
    "axios",
]
