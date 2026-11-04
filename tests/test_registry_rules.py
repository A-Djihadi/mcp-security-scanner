"""T17 + T18 + T19 — registry-backed dependency rules (issue #4).

Covers ``DEP-outdated`` (latest-version comparison), ``DEP-known-vulnerability``
(OSV.dev querybatch + full records), and ``DEP-unknown`` (typosquat via
Damerau-Levenshtein against an injected seed list). Every rule is ``online=True``
and driven through a fake provider, so no test touches the network.

API facts marked "to verify" (OSV.dev query/response shape, pagination, PyPI/npm
latest-version fields, seed-list source, distance threshold) are pinned by the
fake providers and fixtures here rather than asserted against a live service.
"""

from __future__ import annotations

import io
import json
import urllib.request

from mcpsec import rules
from mcpsec.model import RuleRegistry, SourceLocation, Target, TargetKind
from mcpsec.rules.dependency_registry import (
    DEPKnownVulnerability,
    DEPOutdated,
    DEPUnknown,
    damerau_levenshtein,
)
from mcpsec.sarif import SARIFWriter
from mcpsec.sources import DataUnavailable, OSVProvider


def _dep(name, version_spec, pinned, manifest="requirements.txt", line=1):
    return Target(
        kind=TargetKind.DEPENDENCY,
        name=name,
        location=SourceLocation(path=manifest, start_line=line, start_column=1),
        payload={
            "version_spec": version_spec,
            "manifest": manifest,
            "pinned": pinned,
            "source": f"{name}{version_spec}",
        },
    )


class _FakeLatestProvider:
    """Records calls and returns a fixed version (or raises)."""

    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error
        self.calls = []

    def latest_version(self, name):
        self.calls.append(name)
        if self._error is not None:
            raise self._error
        return self._result


class _FakeVulnProvider:
    """Returns a fixed set of vuln summaries + full records (or raises)."""

    def __init__(self, vulns=None, records=None, error=None):
        self._vulns = vulns if vulns is not None else []
        self._records = records if records is not None else {}
        self._error = error
        self.query_calls = []
        self.record_calls = []

    def query_vulns(self, queries):
        self.query_calls.append(queries)
        if self._error is not None:
            raise self._error
        return list(self._vulns)

    def get_vuln(self, vuln_id):
        self.record_calls.append(vuln_id)
        if self._error is not None:
            raise self._error
        return self._records.get(vuln_id)


class _FakePopularProvider:
    def __init__(self, packages=None, error=None):
        self._packages = packages if packages is not None else []
        self._error = error
        self.calls = 0

    def popular_packages(self):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return list(self._packages)


def _assert_diagnostic(finding, rule_id):
    assert finding.rule_id == rule_id
    assert finding.level == "note"
    assert "data unavailable" in finding.message


# --------------------------------------------------------------------------- #
# T17 — DEP-outdated
# --------------------------------------------------------------------------- #
def test_outdated_pinned_python_dep_triggers_warning():
    pypi = _FakeLatestProvider("3.0.0")
    rule = DEPOutdated(pypi_provider=pypi, npm_provider=_FakeLatestProvider("3.0.0"))
    findings = rule.check(_dep("flask", "==2.0.0", True, line=4))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DEP-outdated"
    assert finding.level == "warning"
    assert finding.location.start_line == 4
    assert "flask" in finding.message
    assert "2.0.0" in finding.message
    assert "3.0.0" in finding.message
    assert pypi.calls == ["flask"]


def test_outdated_npm_dep_uses_npm_provider():
    npm = _FakeLatestProvider("2.0.0")
    rule = DEPOutdated(pypi_provider=_FakeLatestProvider("2.0.0"), npm_provider=npm)
    findings = rule.check(_dep("express", "1.0.0", True, manifest="package.json"))
    assert len(findings) == 1
    assert findings[0].rule_id == "DEP-outdated"
    assert npm.calls == ["express"]


def test_dep_equal_to_latest_yields_nothing():
    rule = DEPOutdated(
        pypi_provider=_FakeLatestProvider("2.0.0"), npm_provider=_FakeLatestProvider(None)
    )
    assert rule.check(_dep("flask", "==2.0.0", True)) == []


def test_unpinned_dep_is_skipped_by_outdated():
    rule = DEPOutdated(
        pypi_provider=_FakeLatestProvider("9.9.9"), npm_provider=_FakeLatestProvider(None)
    )
    assert rule.check(_dep("flask", ">=2.0", False)) == []


def test_unknown_package_404_yields_nothing_for_outdated():
    rule = DEPOutdated(
        pypi_provider=_FakeLatestProvider(None), npm_provider=_FakeLatestProvider(None)
    )
    assert rule.check(_dep("no-such-package", "==1.0.0", True)) == []


def test_outdated_data_unavailable_yields_note_diagnostic():
    rule = DEPOutdated(
        pypi_provider=_FakeLatestProvider(error=DataUnavailable("boom")),
        npm_provider=_FakeLatestProvider(None),
    )
    findings = rule.check(_dep("flask", "==2.0.0", True))
    assert len(findings) == 1
    _assert_diagnostic(findings[0], "DEP-outdated")


# --------------------------------------------------------------------------- #
# T18 — DEP-known-vulnerability
# --------------------------------------------------------------------------- #
_RECORD = {"affected": [{"ecosystem_specific": {"severity": "HIGH"}}]}


def test_one_vuln_yields_error_finding_naming_severity():
    provider = _FakeVulnProvider(
        vulns=[{"id": "GHSA-xxxx", "modified": "2024-01-01T00:00:00Z"}],
        records={"GHSA-xxxx": _RECORD},
    )
    rule = DEPKnownVulnerability(provider)
    findings = rule.check(_dep("flask", "==2.0.0", True))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DEP-known-vulnerability"
    assert finding.level == "error"
    assert "flask" in finding.message
    assert "2.0.0" in finding.message
    assert "GHSA-xxxx" in finding.message
    assert "HIGH" in finding.message
    assert provider.record_calls == ["GHSA-xxxx"]


def test_zero_vulns_yields_nothing():
    rule = DEPKnownVulnerability(_FakeVulnProvider(vulns=[]))
    assert rule.check(_dep("flask", "==2.0.0", True)) == []


def test_unpinned_dep_is_skipped_by_vulnerability():
    rule = DEPKnownVulnerability(_FakeVulnProvider(vulns=[{"id": "GHSA-xxxx"}]))
    assert rule.check(_dep("flask", ">=2.0", False)) == []


def test_vulnerability_data_unavailable_yields_note_diagnostic():
    rule = DEPKnownVulnerability(_FakeVulnProvider(error=DataUnavailable("boom")))
    findings = rule.check(_dep("flask", "==2.0.0", True))
    assert len(findings) == 1
    _assert_diagnostic(findings[0], "DEP-known-vulnerability")


def test_osv_query_vulns_follows_pagination(monkeypatch):
    calls = []

    def _urlopen(request, **kwargs):
        body = json.loads(request.data) if request.data else {}
        calls.append(body)
        has_token = any(q.get("page_token") for q in body.get("queries", []))
        if not has_token:
            payload = {
                "results": [
                    {
                        "vulns": [{"id": "A", "modified": "t1"}],
                        "next_page_token": "tok1",
                    }
                ]
            }
        else:
            payload = {"results": [{"vulns": [{"id": "B", "modified": "t2"}]}]}
        return io.BytesIO(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    provider = OSVProvider()
    vulns = provider.query_vulns(
        [{"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "2.0.0"}]
    )
    assert [v["id"] for v in vulns] == ["A", "B"]
    assert len(calls) == 2
    assert calls[1]["queries"][0]["page_token"] == "tok1"


# --------------------------------------------------------------------------- #
# T19 — DEP-unknown / typosquat
# --------------------------------------------------------------------------- #
def test_near_name_is_flagged_as_unknown():
    provider = _FakePopularProvider(["requests", "flask", "numpy"])
    rule = DEPUnknown(provider, threshold=1)
    findings = rule.check(_dep("reqeusts", "==2.0.0", True))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DEP-unknown"
    assert finding.level == "warning"
    assert "reqeusts" in finding.message
    assert "requests" in finding.message


def test_exact_popular_name_yields_nothing():
    rule = DEPUnknown(_FakePopularProvider(["requests", "flask", "numpy"]), threshold=1)
    assert rule.check(_dep("requests", "==2.0.0", True)) == []


def test_name_beyond_threshold_yields_nothing():
    rule = DEPUnknown(_FakePopularProvider(["requests", "flask", "numpy"]), threshold=1)
    assert rule.check(_dep("completely-different", "==1.0.0", True)) == []


def test_threshold_is_injected_and_pins_boundary():
    packages = ["flask"]
    name = "flaskkk"  # distance 2 from "flask"
    assert damerau_levenshtein(name, "flask") == 2

    assert DEPUnknown(_FakePopularProvider(packages), threshold=1).check(
        _dep(name, "==1.0.0", True)
    ) == []
    findings = DEPUnknown(_FakePopularProvider(packages), threshold=2).check(
        _dep(name, "==1.0.0", True)
    )
    assert len(findings) == 1


def test_unknown_data_unavailable_yields_note_diagnostic():
    rule = DEPUnknown(_FakePopularProvider(error=DataUnavailable("boom")), threshold=1)
    findings = rule.check(_dep("reqeusts", "==2.0.0", True))
    assert len(findings) == 1
    _assert_diagnostic(findings[0], "DEP-unknown")


def test_damerau_levenshtein_counts_single_transposition():
    assert damerau_levenshtein("reqeusts", "requests") == 1
    assert damerau_levenshtein("", "") == 0
    assert damerau_levenshtein("a", "") == 1
    assert damerau_levenshtein("", "a") == 1
    assert damerau_levenshtein("kitten", "sitting") == 3


# --------------------------------------------------------------------------- #
# Registration: online rules gated behind --online (ADR-0007).
# --------------------------------------------------------------------------- #
def test_online_rules_absent_by_default_present_under_online():
    offline = rules.build_default_registry()
    for rule_id in ("DEP-outdated", "DEP-known-vulnerability", "DEP-unknown"):
        assert rule_id not in offline

    online = rules.build_default_registry(online=True)
    for rule_id in ("DEP-outdated", "DEP-known-vulnerability", "DEP-unknown"):
        assert rule_id in online
        assert online.get(rule_id).online is True


def test_online_rule_finding_carries_mode_online_in_sarif():
    rule = DEPKnownVulnerability(
        _FakeVulnProvider(
            vulns=[{"id": "GHSA-xxxx", "modified": "t1"}],
            records={"GHSA-xxxx": _RECORD},
        )
    )
    finding = rule.check(_dep("flask", "==2.0.0", True))[0]
    reg = RuleRegistry()
    reg.register(rule)
    doc = SARIFWriter().render([finding], reg, online=True)
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["mode"] == "online"
    assert result["properties"]["vuln_id"] == "GHSA-xxxx"
    assert doc["runs"][0]["properties"]["mcpsec"]["online"] is True


def test_diagnostic_finding_still_carries_mode_online():
    rule = DEPKnownVulnerability(_FakeVulnProvider(error=DataUnavailable("boom")))
    finding = rule.check(_dep("flask", "==2.0.0", True))[0]
    reg = RuleRegistry()
    reg.register(rule)
    doc = SARIFWriter().render([finding], reg, online=True)
    result = doc["runs"][0]["results"][0]
    assert result["level"] == "note"
    assert result["properties"]["mode"] == "online"
    assert result["properties"]["data_unavailable"] is True
