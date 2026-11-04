"""T15 — remote MCP offline hygiene rules (pure, no I/O).

``MCP-insecure-transport`` (error), ``MCP-header-secret`` (warning), and
``MCP-remote-no-auth`` (note) over remote-server targets. Each is unit-tested
through ``check(target)`` with hand-built targets; none does I/O or holds state.
"""

from __future__ import annotations

import socket
import urllib.request

from mcpsec import cli
from mcpsec.model import RuleRegistry, SourceLocation, Target, TargetKind
from mcpsec.rules import (
    MCPHeaderSecret,
    MCPInsecureTransport,
    MCPRemoteNoAuth,
    MCPUnreachable,
    MCPUnreachableDiagnostic,
    build_default_registry,
)
from mcpsec.sarif import SARIFWriter
from mcpsec.sources import DataUnavailable


def _loc(path="mcp.json", line=1, col=1):
    return SourceLocation(path=path, start_line=line, start_column=col)


def _server(
    name="srv",
    *,
    transport="stdio",
    url=None,
    type_=None,
    headers=None,
    field_locations=None,
    path="mcp.json",
):
    payload = {
        "command": None,
        "args": [],
        "env": {},
        "cwd": None,
        "transport": transport,
        "url": url,
        "type": type_,
        "headers": headers or {},
    }
    return Target(
        kind=TargetKind.MCP_SERVER,
        name=name,
        location=_loc(path),
        payload=payload,
        field_locations=field_locations or {},
    )


# --- MCP-insecure-transport --------------------------------------------------


def test_insecure_transport_flags_plain_http_url():
    rule = MCPInsecureTransport()
    url_loc = _loc("mcp.json", line=3, col=12)
    target = _server(
        name="r", transport="remote", url="http://example.com/mcp",
        field_locations={"url": url_loc},
    )
    findings = rule.check(target)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "MCP-insecure-transport"
    assert f.level == "error"
    assert f.location == url_loc


def test_insecure_transport_ignores_https_and_wss():
    rule = MCPInsecureTransport()
    for url in ("https://example.com/mcp", "wss://example.com/mcp"):
        target = _server(name="r", transport="remote", url=url)
        assert rule.check(target) == [], url


def test_insecure_transport_ignores_remote_without_url():
    rule = MCPInsecureTransport()
    assert rule.check(_server(name="r", transport="remote", url=None)) == []


def test_insecure_transport_ignores_stdio_and_non_server():
    rule = MCPInsecureTransport()
    assert rule.check(_server(name="s", transport="stdio")) == []
    skill = Target(kind=TargetKind.SKILL, name="s", location=_loc(path="SKILL.md"))
    assert rule.check(skill) == []


# --- MCP-header-secret -------------------------------------------------------


def test_header_secret_flags_authorization_bearer_at_header_location():
    rule = MCPHeaderSecret()
    auth_loc = _loc("mcp.json", line=7, col=26)
    target = _server(
        name="r",
        transport="remote",
        url="https://example.com/mcp",
        headers={"Authorization": "Bearer sk-abcdef123456"},
        field_locations={"headers": {"Authorization": auth_loc}},
    )
    findings = rule.check(target)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "MCP-header-secret"
    assert f.level == "warning"
    assert f.location == auth_loc


def test_header_secret_flags_x_api_key():
    rule = MCPHeaderSecret()
    api_loc = _loc("mcp.json", line=8, col=20)
    target = _server(
        name="r",
        transport="remote",
        url="https://example.com/mcp",
        headers={"X-API-Key": "sk-abcdef123456"},  # gitleaks:allow (fake test key, not a real secret)
        field_locations={"headers": {"X-API-Key": api_loc}},
    )
    findings = rule.check(target)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-header-secret"
    assert findings[0].location == api_loc


def test_header_secret_flags_secret_literal_in_value():
    rule = MCPHeaderSecret()
    loc = _loc("mcp.json", line=8, col=20)
    target = _server(
        name="r",
        transport="remote",
        url="https://example.com/mcp",
        headers={"X-Custom": "token ghp_abcdefghijklmnopqrstuvwx"},
        field_locations={"headers": {"X-Custom": loc}},
    )
    findings = rule.check(target)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-header-secret"


def test_header_secret_ignores_benign_headers():
    rule = MCPHeaderSecret()
    target = _server(
        name="r",
        transport="remote",
        url="https://example.com/mcp",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    assert rule.check(target) == []


def test_header_secret_ignores_env_placeholder_values():
    rule = MCPHeaderSecret()
    target = _server(
        name="r",
        transport="remote",
        url="https://example.com/mcp",
        headers={"Authorization": "Bearer ${GITHUB_TOKEN}"},
    )
    assert rule.check(target) == []


# --- MCP-remote-no-auth ------------------------------------------------------


def test_remote_no_auth_flags_remote_without_auth_header():
    rule = MCPRemoteNoAuth()
    target = _server(
        name="r", transport="remote", url="https://example.com/mcp", headers={}
    )
    findings = rule.check(target)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "MCP-remote-no-auth"
    assert f.level == "note"


def test_remote_no_auth_ignores_remote_with_bearer_header():
    rule = MCPRemoteNoAuth()
    target = _server(
        name="r",
        transport="remote",
        url="https://example.com/mcp",
        headers={"Authorization": "Bearer token"},
    )
    assert rule.check(target) == []


def test_remote_no_auth_ignores_remote_with_api_key_header():
    rule = MCPRemoteNoAuth()
    target = _server(
        name="r",
        transport="remote",
        url="https://example.com/mcp",
        headers={"X-API-Key": "sk-abcdef123456"},  # gitleaks:allow (fake test key, not a real secret)
    )
    assert rule.check(target) == []


def test_remote_no_auth_ignores_stdio_and_non_server():
    rule = MCPRemoteNoAuth()
    assert rule.check(_server(name="s", transport="stdio")) == []
    skill = Target(kind=TargetKind.SKILL, name="s", location=_loc(path="SKILL.md"))
    assert rule.check(skill) == []


# --- purity ----------------------------------------------------------------


def test_t15_rules_are_pure_and_registered_as_offline():
    for rule in (MCPInsecureTransport(), MCPHeaderSecret(), MCPRemoteNoAuth()):
        assert rule.online is False
        # Two identical checks yield identical findings (no state).
        target = _server(
            name="r", transport="remote", url="http://example.com/mcp"
        )
        assert rule.check(target) == rule.check(target)


# --- T16 — MCP-unreachable (online) -----------------------------------------


class _FakeProvider:
    def __init__(self, result: str = "reachable", error=None):
        self._result = result
        self._error = error
        self.calls = []

    def probe(self, url: str) -> str:
        self.calls.append(url)
        if self._error is not None:
            raise self._error
        return self._result


def _run(argv, capsys):
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_unreachable_flags_unreachable_at_url_location():
    url_loc = _loc("mcp.json", line=3, col=12)
    target = _server(
        name="r",
        transport="remote",
        url="https://example.com/mcp",
        field_locations={"url": url_loc},
    )
    findings = MCPUnreachable(_FakeProvider(result="unreachable")).check(target)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "MCP-unreachable"
    assert f.level == "note"
    assert f.location == url_loc


def test_unreachable_no_finding_when_reachable():
    target = _server(name="r", transport="remote", url="https://example.com/mcp")
    assert MCPUnreachable(_FakeProvider(result="reachable")).check(target) == []


def test_unreachable_ignores_non_remote_and_missing_url():
    rule = MCPUnreachable(_FakeProvider(result="unreachable"))
    assert rule.check(_server(name="s", transport="stdio")) == []
    assert rule.check(_server(name="r", transport="remote", url=None)) == []


def test_unreachable_data_unavailable_yields_note_diagnostic():
    target = _server(name="r", transport="remote", url="https://example.com/mcp")
    findings = MCPUnreachable(
        _FakeProvider(error=DataUnavailable("boom"))
    ).check(target)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "MCP-unreachable-diagnostic"
    assert f.rule_id != "MCP-unreachable"
    assert f.level == "note"


def test_unreachable_registered_only_under_online():
    assert "MCP-unreachable" not in build_default_registry()
    assert "MCP-unreachable-diagnostic" not in build_default_registry()

    online = build_default_registry(online=True)
    assert "MCP-unreachable" in online
    assert "MCP-unreachable-diagnostic" in online


def test_unreachable_finding_carries_mode_online_in_sarif():
    registry = RuleRegistry()
    registry.register(MCPUnreachable(_FakeProvider(result="unreachable")))
    registry.register(MCPUnreachableDiagnostic())
    target = _server(name="r", transport="remote", url="https://example.com/mcp")

    rule = registry.get("MCP-unreachable")
    assert rule is not None
    findings = rule.check(target)
    doc = SARIFWriter().render(findings, registry, online=True)
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "MCP-unreachable"
    assert result["properties"] == {"mode": "online"}


def test_default_scan_over_remote_mcp_performs_no_network(tmp_path, monkeypatch, capsys):
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"r": {"type": "sse", "url": "https://example.com/mcp"}}}',
        encoding="utf-8",
    )
    touched = []

    def _boom(*args, **kwargs):
        touched.append((args, kwargs))
        raise AssertionError("network touched during offline scan")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    code, out, _ = _run(["scan", str(tmp_path), "--format", "text"], capsys)
    assert touched == []
    assert "MCP-unreachable" not in out
    assert code == 0


def test_online_provider_failure_is_note_and_does_not_change_exit_code(
    tmp_path, monkeypatch, capsys
):
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"r": {"type": "sse", "url": "https://example.com/mcp"}}}',
        encoding="utf-8",
    )

    class FailingProbe:
        def probe(self, url: str) -> str:
            raise DataUnavailable("boom")

    registry = RuleRegistry()
    registry.register(MCPUnreachable(FailingProbe()))
    registry.register(MCPUnreachableDiagnostic())
    monkeypatch.setattr(
        cli, "build_default_registry", lambda *, online=False, **kw: registry
    )

    code, out, _ = _run(
        ["scan", str(tmp_path), "--format", "text", "--online"], capsys
    )
    assert code == 0
    assert "MCP-unreachable-diagnostic" in out


