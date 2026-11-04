"""Registry-backed dependency rules (T17/T18/T19, issue #4).

Three ``online=True`` rules that consume an injected data provider and stay
I/O-free in ``check()`` (ADR-0007):

* ``DEP-outdated`` — a pinned dependency is behind the registry's latest version.
* ``DEP-known-vulnerability`` — a resolved dependency has a known OSV.dev advisory.
* ``DEP-unknown`` — a dependency name is suspiciously close to a popular package
  (typosquat signal) via Damerau-Levenshtein distance against a popularity-ranked
  seed list.

Every provider ``DataUnavailable`` is translated to a note-level diagnostic, never
an error finding and never a crash (ADR-0007). Unpinned dependencies are skipped
(that is ``DEP-unpinned``'s concern), and a 404 (unknown package) is "no data",
never a false verdict.
"""

from __future__ import annotations

from ..model import Finding, Target, TargetKind
from ..sources import DataUnavailable

# The default typosquat distance threshold. The exact value (and whether it
# should scale with name length) is "to verify" (ADR-0007); the rule always
# accepts an injected threshold so callers can pin a different value.
DEFAULT_TYPOSQUAT_THRESHOLD = 1  # to verify


def _is_dependency(target: Target) -> bool:
    return target.kind is TargetKind.DEPENDENCY


def _is_pinned(target: Target) -> bool:
    return target.payload.get("pinned") is True


def _ecosystem(manifest: str | None) -> str:
    """Map a manifest filename to an OSV/npm ecosystem label."""
    base = (manifest or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return "npm" if base == "package.json" else "PyPI"


def _declared_version(version_spec: str | None) -> str | None:
    """Extract the pinned version number from a PEP 508 or npm version spec."""
    spec = (version_spec or "").strip()
    if not spec:
        return None
    if spec.startswith("==="):
        spec = spec[3:].strip()
    elif spec.startswith("=="):
        spec = spec[2:].strip()
    return spec or None


def _data_unavailable_finding(rule_id: str, target: Target, what: str) -> Finding:
    """A note-level diagnostic for a provider failure (never an error verdict)."""
    return Finding(
        rule_id=rule_id,
        level="note",
        message=(
            f'could not check dependency "{target.name}" for {what} '
            "(data unavailable)"
        ),
        location=target.location,
        properties={"data_unavailable": True},
    )


class DEPOutdated:
    """Flag a pinned dependency whose declared version is behind the latest."""

    id = "DEP-outdated"
    level = "warning"
    short_description = "Declared dependency version is behind the latest published version."
    online = True

    def __init__(self, *, pypi_provider, npm_provider) -> None:
        self._pypi = pypi_provider
        self._npm = npm_provider

    def check(self, target: Target) -> list[Finding]:
        if not _is_dependency(target) or not _is_pinned(target):
            return []
        declared = _declared_version(target.payload.get("version_spec"))
        if declared is None:
            return []

        ecosystem = _ecosystem(target.payload.get("manifest"))
        provider = self._npm if ecosystem == "npm" else self._pypi
        try:
            latest = provider.latest_version(target.name)
        except DataUnavailable:
            return [_data_unavailable_finding(self.id, target, "an outdated version")]

        if latest is None:
            return []  # 404: unknown package is "no data", not "outdated"
        if latest == declared:
            return []

        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'dependency "{target.name}" is outdated: '
                    f'declared "{declared}", latest "{latest}"'
                ),
                location=target.location,
                properties={
                    "ecosystem": ecosystem,
                    "declared": declared,
                    "latest": latest,
                },
            )
        ]


def _severity(record: dict) -> str | None:
    """Extract a severity string from an OSV vulnerability record.

    Prefers the ecosystem-specific severity (e.g. GHSA ``HIGH``); falls back to
    the top-level CVSS score. Exact field names are "to verify" and pinned by the
    test fixtures.
    """
    affected = record.get("affected")
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            eco = entry.get("ecosystem_specific")
            if isinstance(eco, dict) and eco.get("severity"):
                return eco["severity"]
    sev = record.get("severity")
    if isinstance(sev, list) and sev:
        first = sev[0]
        if isinstance(first, dict) and first.get("score"):
            return first["score"]
    return None


class DEPKnownVulnerability:
    """Flag a resolved dependency with a known OSV.dev vulnerability."""

    id = "DEP-known-vulnerability"
    level = "error"
    short_description = "Dependency version has a known vulnerability (OSV.dev)."
    online = True

    def __init__(self, provider) -> None:
        self._provider = provider

    def check(self, target: Target) -> list[Finding]:
        if not _is_dependency(target) or not _is_pinned(target):
            return []
        version = _declared_version(target.payload.get("version_spec"))
        if version is None:
            return []

        ecosystem = _ecosystem(target.payload.get("manifest"))
        query = {
            "package": {"name": target.name, "ecosystem": ecosystem},
            "version": version,
        }
        try:
            vulns = self._provider.query_vulns([query])
        except DataUnavailable:
            return [_data_unavailable_finding(self.id, target, "known vulnerabilities")]

        findings: list[Finding] = []
        for summary in vulns:
            vuln_id = summary.get("id") if isinstance(summary, dict) else None
            if not vuln_id:
                continue
            try:
                record = self._provider.get_vuln(vuln_id)
            except DataUnavailable:
                findings.append(
                    _data_unavailable_finding(self.id, target, f"vulnerability {vuln_id}")
                )
                continue
            if not isinstance(record, dict):
                continue  # 404 on the record is "no data"
            severity = _severity(record)
            severity_text = severity if severity else "severity unavailable"
            findings.append(
                Finding(
                    rule_id=self.id,
                    level=self.level,
                    message=(
                        f'dependency "{target.name}" version "{version}" has known '
                        f'vulnerability "{vuln_id}" ({severity_text})'
                    ),
                    location=target.location,
                    properties={
                        "ecosystem": ecosystem,
                        "version": version,
                        "vuln_id": vuln_id,
                        "severity": severity,
                    },
                )
            )
        return findings


def damerau_levenshtein(a: str, b: str) -> int:
    """Restricted Damerau-Levenshtein (optimal string alignment) distance.

    Counts insertions, deletions, substitutions, and single adjacent
    transpositions. This is the standard "Damerau-Levenshtein" used for
    typosquat detection; whether the full (unrestricted) variant is warranted is
    "to verify" (ADR-0007).
    """
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la

    rows = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        rows[i][0] = i
    for j in range(lb + 1):
        rows[0][j] = j

    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(
                rows[i - 1][j] + 1,      # deletion
                rows[i][j - 1] + 1,      # insertion
                rows[i - 1][j - 1] + cost,  # substitution
            )
            if (
                i > 1
                and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)  # transposition
    return rows[la][lb]


class DEPUnknown:
    """Flag a dependency name suspiciously close to a popular package."""

    id = "DEP-unknown"
    level = "warning"
    short_description = (
        "Dependency name closely resembles a popular package (typosquat signal)."
    )
    online = True

    def __init__(self, provider, threshold: int = DEFAULT_TYPOSQUAT_THRESHOLD) -> None:
        self._provider = provider
        self._threshold = threshold

    def check(self, target: Target) -> list[Finding]:
        if not _is_dependency(target):
            return []
        name = target.name
        if not name:
            return []

        try:
            popular = self._provider.popular_packages()
        except DataUnavailable:
            return [_data_unavailable_finding(self.id, target, "a typosquat check")]

        candidates = [p for p in popular if isinstance(p, str) and p != name]
        best: str | None = None
        best_distance: int | None = None
        for candidate in candidates:
            distance = damerau_levenshtein(name, candidate)
            if best_distance is None or distance < best_distance:
                best_distance = distance
                best = candidate

        if best is None or best_distance is None or best_distance > self._threshold:
            return []

        return [
            Finding(
                rule_id=self.id,
                level=self.level,
                message=(
                    f'dependency "{name}" closely resembles popular package '
                    f'"{best}" (typosquat signal)'
                ),
                location=target.location,
                properties={
                    "near_match": best,
                    "distance": best_distance,
                    "threshold": self._threshold,
                },
            )
        ]
