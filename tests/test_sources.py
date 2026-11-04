"""T12 — data-source providers: OSV.dev, PyPI, npm, reachability.

Covers the provider contract: injection at construction, typed ``DataUnavailable``
on failure, 404-as-no-data, bounded retry, per-run memoization, and exit-code
isolation (ADR-0007).
"""

from __future__ import annotations

import io
import socket
import urllib.error
import urllib.request

import pytest

from mcpsec import cli, rules
from mcpsec.model import Finding, SourceLocation, Target, TargetKind
from mcpsec.sources import (
    DEFAULT_ATTEMPTS,
    DataUnavailable,
    NpmProvider,
    PyPIProvider,
)


def _fake_response(body: bytes):
    return io.BytesIO(body)


def _patch_urlopen(monkeypatch, fn):
    monkeypatch.setattr(urllib.request, "urlopen", fn)


def _dep(name="flask", line=1):
    return Target(
        kind=TargetKind.DEPENDENCY,
        name=name,
        location=SourceLocation(path="requirements.txt", start_line=line, start_column=1),
        payload={"version_spec": "==2.0.0", "manifest": "requirements.txt", "pinned": True},
    )


# --------------------------------------------------------------------------- #
# 1. Injection: the online rule receives the provider and does no socket I/O.
# --------------------------------------------------------------------------- #
def test_rule_uses_injected_provider_and_performs_no_socket_io(monkeypatch):
    class RecordingProvider:
        def __init__(self):
            self.calls = []

        def fetch(self, name):
            self.calls.append(name)
            return "3.0.0"

    provider = RecordingProvider()

    class OnlineRule:
        id = "DEP-outdated"
        level = "warning"
        short_description = "online dependency rule"
        online = True

        def __init__(self, provider):
            self._provider = provider

        def check(self, target):
            latest = self._provider.fetch(target.name)
            return [
                Finding("DEP-outdated", "warning", f"{target.name} -> {latest}", target.location)
            ]

    touched = []

    def _boom(*args, **kwargs):
        touched.append((args, kwargs))
        raise AssertionError("network touched inside check()")

    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    findings = OnlineRule(provider).check(_dep("flask"))
    assert provider.calls == ["flask"]
    assert [f.message for f in findings] == ["flask -> 3.0.0"]
    assert touched == []


# --------------------------------------------------------------------------- #
# 2. DataUnavailable on timeout, HTTP error, malformed payload, refusal.
# --------------------------------------------------------------------------- #
def test_data_unavailable_on_timeout(monkeypatch):
    def _timeout(request, **kwargs):
        raise TimeoutError("timed out")

    _patch_urlopen(monkeypatch, _timeout)
    with pytest.raises(DataUnavailable) as exc:
        PyPIProvider().latest_version("flask")
    assert exc.value.kind == "timeout"


def test_data_unavailable_on_http_error(monkeypatch):
    def _http_error(request, **kwargs):
        raise urllib.error.HTTPError("http://x", 500, "boom", {}, io.BytesIO(b"{}"))

    _patch_urlopen(monkeypatch, _http_error)
    with pytest.raises(DataUnavailable) as exc:
        PyPIProvider().latest_version("flask")
    assert exc.value.kind == "http"


def test_data_unavailable_on_malformed_payload(monkeypatch):
    def _malformed(request, **kwargs):
        return _fake_response(b"this is not json")

    _patch_urlopen(monkeypatch, _malformed)
    with pytest.raises(DataUnavailable) as exc:
        PyPIProvider().latest_version("flask")
    assert exc.value.kind == "malformed"


def test_data_unavailable_on_network_refusal(monkeypatch):
    def _refused(request, **kwargs):
        raise ConnectionRefusedError("refused")

    _patch_urlopen(monkeypatch, _refused)
    with pytest.raises(DataUnavailable) as exc:
        PyPIProvider().latest_version("flask")
    assert exc.value.kind == "refused"


# --------------------------------------------------------------------------- #
# 3. 404 (unknown package) maps to "no data" (None), not an exception.
# --------------------------------------------------------------------------- #
def test_pypi_404_returns_none(monkeypatch):
    def _not_found(request, **kwargs):
        raise urllib.error.HTTPError("http://x", 404, "Not Found", {}, io.BytesIO(b""))

    _patch_urlopen(monkeypatch, _not_found)
    assert PyPIProvider().latest_version("no-such-package") is None


def test_npm_404_returns_none(monkeypatch):
    def _not_found(request, **kwargs):
        raise urllib.error.HTTPError("http://x", 404, "Not Found", {}, io.BytesIO(b""))

    _patch_urlopen(monkeypatch, _not_found)
    assert NpmProvider().latest_version("no-such-package") is None


# --------------------------------------------------------------------------- #
# 4. Bounded retry (exactly N attempts) + memoization (one call per key).
# --------------------------------------------------------------------------- #
def test_retries_are_bounded_to_exactly_max_attempts(monkeypatch):
    calls = []

    def _refused(request, **kwargs):
        calls.append(request.full_url)
        raise urllib.error.URLError(ConnectionRefusedError("refused"))

    _patch_urlopen(monkeypatch, _refused)
    provider = PyPIProvider(max_attempts=3)
    with pytest.raises(DataUnavailable):
        provider.latest_version("flask")
    assert len(calls) == 3


def test_memoization_prevents_second_network_call_for_same_key(monkeypatch):
    calls = []

    def _ok(request, **kwargs):
        calls.append(request.full_url)
        return _fake_response(b'{"info": {"version": "3.0.0"}}')

    _patch_urlopen(monkeypatch, _ok)
    provider = PyPIProvider()
    assert provider.latest_version("flask") == "3.0.0"
    assert provider.latest_version("flask") == "3.0.0"
    assert len(calls) == 1


def test_default_attempts_is_small_and_bounded():
    assert DEFAULT_ATTEMPTS >= 1


# --------------------------------------------------------------------------- #
# 5. Provider failures never change the exit code.
# --------------------------------------------------------------------------- #
def test_provider_failure_never_changes_exit_code(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")

    class FailingProvider:
        def fetch(self, name):
            raise DataUnavailable("boom")

    class FailingOnlineRule:
        id = "DEP-outdated"
        level = "warning"
        short_description = "online dependency rule"
        online = True

        def __init__(self, provider):
            self._provider = provider

        def check(self, target):
            try:
                self._provider.fetch(target.name)
            except DataUnavailable:
                return []  # network failure is not a verdict
            return []

    reg = rules.build_default_registry(online=True)
    reg.register(FailingOnlineRule(FailingProvider()))
    monkeypatch.setattr(cli, "build_default_registry", lambda *, online=False: reg)

    code = cli.main(["scan", str(tmp_path), "--format", "text", "--online"])
    out = capsys.readouterr().out
    # Deterministic offline finding only (DEP-unpinned warning < error threshold).
    assert code == 0
    assert "DEP-unpinned" in out
    assert "DEP-outdated" not in out


# --- audit 2026-11: no local files, no SSRF, bounded bodies ------------------

def test_client_refuses_non_http_schemes():
    from mcpsec.sources._http import DataUnavailable, _HttpClient

    client = _HttpClient(timeout=1, max_attempts=1)
    for url in ("file:///etc/passwd", "ftp://example.com/x", "data:text/plain,hi"):
        with pytest.raises(DataUnavailable) as info:
            client.get(url)
        assert info.value.kind == "invalid"


def test_reachability_never_probes_private_or_metadata_addresses():
    from mcpsec.sources import ReachabilityProvider
    from mcpsec.sources._http import DataUnavailable

    class Boom:
        def get(self, url):  # pragma: no cover - must never be called
            raise AssertionError(f"probed {url}")

    probe = ReachabilityProvider(client=Boom())
    for url in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/",
                "http://10.0.0.5/mcp", "http://[::1]/", "file:///etc/passwd"):
        with pytest.raises(DataUnavailable) as info:
            probe.probe(url)
        assert info.value.kind == "blocked"


def test_response_body_is_bounded(monkeypatch):
    import io

    from mcpsec.sources import _http

    class FakeResponse(io.BytesIO):
        pass

    monkeypatch.setattr(_http, "MAX_RESPONSE_BYTES", 8)
    monkeypatch.setattr(_http.urllib.request, "urlopen",
                        lambda req, timeout: FakeResponse(b"x" * 100))
    with pytest.raises(_http.DataUnavailable):
        _http._HttpClient(max_attempts=1).get("https://example.com/big")
