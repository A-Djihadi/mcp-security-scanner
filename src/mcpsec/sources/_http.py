"""Private HTTP machinery for data-source providers.

All network I/O in the scanner lives here (and in the providers that use it),
never in a rule (ADR-0007). Uses only the standard-library ``urllib`` so the base
install stays PyYAML-only. A request is bounded in time (``timeout``), bounded in
attempts (``max_attempts``), and memoized per client instance for the duration of
a run.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

# Bounded defaults. The exact values are "to verify" against the real rate limits
# and Terms of Service of PyPI, npm, and OSV.dev before shipping (ADR-0007).
DEFAULT_TIMEOUT = 10.0  # seconds — to verify
DEFAULT_ATTEMPTS = 2  # total attempts — to verify
# Upper bound on a response body: a hostile endpoint must not exhaust memory.
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_ALLOWED_SCHEMES = frozenset({"http", "https"})


class DataUnavailable(Exception):
    """A data source could not return usable data.

    Raised on timeout, a non-404 HTTP error, a malformed payload, or a network
    refusal. It never crashes the scan: online rules translate it to a
    note-level diagnostic and it never becomes an error verdict (ADR-0007).

    ``kind`` discriminates the cause for callers that treat some failures as a
    definite outcome (e.g. the reachability probe treats "refused" as
    "unreachable" but re-raises a timeout).
    """

    def __init__(self, message: str, *, kind: str = "network") -> None:
        super().__init__(message)
        self.kind = kind


class _HttpClient:
    """Bounded-timeout, bounded-retry, per-run memoized fetcher over ``urllib``."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_ATTEMPTS,
    ) -> None:
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._cache: dict[tuple[Any, ...], Any] = {}

    def get_json(self, url: str) -> Any:
        """GET a JSON resource; ``None`` on 404. Raises ``DataUnavailable``."""
        raw = self._fetch("GET", url)
        if raw is None:
            return None
        return self._parse(url, raw)

    def post_json(self, url: str, payload: dict) -> Any:
        """POST a JSON body; ``None`` on 404. Raises ``DataUnavailable``."""
        raw = self._fetch("POST", url, payload)
        if raw is None:
            return None
        return self._parse(url, raw)

    def get(self, url: str) -> bytes | None:
        """GET raw bytes; ``None`` on 404. Raises ``DataUnavailable``."""
        return self._fetch("GET", url)

    def _fetch(
        self, method: str, url: str, payload: dict | None = None
    ) -> bytes | None:
        key = (
            method,
            url,
            json.dumps(payload, sort_keys=True) if payload is not None else None,
        )
        if key in self._cache:
            return self._cache[key]
        result = self._attempt(method, url, payload)
        self._cache[key] = result
        return result

    def _attempt(
        self, method: str, url: str, payload: dict | None
    ) -> bytes | None:
        scheme = urlsplit(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            # urlopen also serves file:// and ftp:// -- a scanned config must never
            # make the scanner read local files or speak other protocols.
            raise DataUnavailable(f"unsupported URL scheme {scheme!r}", kind="invalid")
        body: bytes | None = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            request = urllib.request.Request(
                url, data=body, headers=headers, method=method
            )
        except ValueError as exc:
            raise DataUnavailable(f"invalid URL {url!r}", kind="network") from exc

        last: DataUnavailable | None = None
        for _ in range(self._max_attempts):
            try:
                response = urllib.request.urlopen(request, timeout=self._timeout)  # nosec B310 - scheme checked above
            except urllib.error.HTTPError as exc:
                # 404 is a normal "no data" result; every other status means the
                # source could not serve usable data (no retry — the server
                # answered).
                if exc.code == 404:
                    return None
                raise DataUnavailable(
                    f"HTTP {exc.code} from {url}", kind="http"
                ) from exc
            except urllib.error.URLError as exc:
                last = _classify_urlerror(exc, url)
            except TimeoutError:
                last = DataUnavailable(f"timeout from {url}", kind="timeout")
            except ConnectionRefusedError:
                last = DataUnavailable(f"connection refused by {url}", kind="refused")
            except OSError as exc:
                last = DataUnavailable(f"network error from {url}: {exc}", kind="network")
            else:
                with response:
                    data = response.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise DataUnavailable(
                        f"response from {url} exceeds {MAX_RESPONSE_BYTES} bytes",
                        kind="malformed",
                    )
                return data

        if last is None:  # pragma: no cover - max_attempts >= 1 always sets it
            raise DataUnavailable(f"no attempt made for {url}", kind="network")
        raise DataUnavailable(
            f"request failed after {self._max_attempts} attempts: {url} ({last})",
            kind=last.kind,
        ) from last

    @staticmethod
    def _parse(url: str, raw: bytes) -> Any:
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise DataUnavailable(
                f"malformed JSON from {url}", kind="malformed"
            ) from exc


def _classify_urlerror(exc: urllib.error.URLError, url: str) -> DataUnavailable:
    reason = exc.reason
    if isinstance(reason, ConnectionRefusedError):
        return DataUnavailable(f"connection refused by {url}", kind="refused")
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return DataUnavailable(f"timeout from {url}", kind="timeout")
    return DataUnavailable(f"network error from {url}: {reason}", kind="network")


def is_public_destination(url: str) -> bool:
    """True if every address ``url``'s host resolves to is a public (global) IP.

    Used before probing a URL taken from a scanned (untrusted) file, so an
    ``--online`` scan in CI cannot be turned into an SSRF against loopback,
    private networks or cloud metadata endpoints (169.254.169.254).
    Residual risk: DNS can change between this check and the request.
    """
    host = urlsplit(url).hostname
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(
        ipaddress.ip_address(addr.split("%", 1)[0]).is_global for addr in addresses
    )
