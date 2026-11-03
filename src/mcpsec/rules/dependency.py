"""Dependency rule: DEP-unpinned."""

from __future__ import annotations

from ..model import Finding, Target, TargetKind


class DEPUnpinned:
    id = "DEP-unpinned"
    level = "warning"
    short_description = "Dependency version is not pinned."

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.DEPENDENCY:
            return []
        if target.payload.get("pinned") is not False:
            return []
        spec = target.payload.get("version_spec", "")
        if spec:
            message = f'dependency "{target.name}" is unpinned (spec "{spec}")'
        else:
            message = f'dependency "{target.name}" is unpinned (no version spec)'
        return [Finding(self.id, self.level, message, target.location)]
