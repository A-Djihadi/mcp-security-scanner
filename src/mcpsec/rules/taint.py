"""Python taint/flow rules (T22, ADR-0009).

Three pure rules sharing one stdlib-``ast`` analyzer: each ``check`` runs the
analysis on a ``python_source`` target and keeps only its own sink category.
The shared analyzer makes the taxonomy (sources, propagators, sinks,
sanitizers) live in one place — see ``mcpsec/taint/analyzer.py``.
"""

from __future__ import annotations

from ..model import Finding, SourceLocation, Target, TargetKind
from ..taint import analyze_python


class _FlowRule:
    id = ""
    level = ""
    short_description = ""

    def check(self, target: Target) -> list[Finding]:
        if target.kind is not TargetKind.PYTHON_SOURCE:
            return []
        source = target.payload.get("source", "")
        return [
            Finding(
                rule_id=tf.rule_id,
                level=self.level,
                message=tf.message,
                location=SourceLocation(
                    path=target.location.path,
                    start_line=tf.line,
                    start_column=tf.column,
                    end_line=tf.end_line,
                    end_column=tf.end_column,
                    snippet=tf.snippet,
                ),
            )
            for tf in analyze_python(source)
            if tf.rule_id == self.id
        ]


class FLOWShellInjection(_FlowRule):
    id = "FLOW-shell-injection"
    level = "error"
    short_description = "Tainted input reaches a shell execution sink."


class FLOWSqlInjection(_FlowRule):
    id = "FLOW-sql-injection"
    level = "error"
    short_description = "Tainted input reaches a SQL query sink."


class FLOWCodeEval(_FlowRule):
    id = "FLOW-code-eval"
    level = "warning"
    short_description = "Tainted input reaches a code-eval sink (eval/exec/compile)."
