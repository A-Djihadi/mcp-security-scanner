"""``requirements.txt`` parser: one ``Dependency`` per declaration line."""

from __future__ import annotations

import re
from pathlib import Path

from ..model import SourceLocation, Target, TargetKind
from ._common import is_pinned_python, normalize_path, split_pep508

_INLINE_COMMENT = re.compile(r"\s+#.*$")


class RequirementsParser:
    """Parse ``requirements.txt`` into ``Dependency`` targets.

    ``pinned`` is true only for ``==``/``===`` specs; empty, wildcard and
    range specs are unpinned.
    """

    def parse(self, path: Path) -> list[Target]:
        text = path.read_text(encoding="utf-8")
        targets: list[Target] = []
        for line_no, raw in enumerate(text.splitlines(), 1):
            line = _INLINE_COMMENT.sub("", raw).strip()
            if not line:
                continue
            if line.startswith(("#", "-r", "--", "-e", "-c", "-i")):
                continue  # comment or include/option line, not a dependency
            name, spec = split_pep508(line)
            if not name:
                continue
            payload = {
                "version_spec": spec,
                "manifest": normalize_path(path),
                "pinned": is_pinned_python(spec),
                "source": line,
            }
            location = SourceLocation(
                path=normalize_path(path), start_line=line_no, start_column=1, snippet=line
            )
            targets.append(
                Target(
                    kind=TargetKind.DEPENDENCY,
                    name=name,
                    location=location,
                    payload=payload,
                )
            )
        return targets
