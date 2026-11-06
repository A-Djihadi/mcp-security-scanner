"""Deterministic Python taint/flow analysis built on stdlib ``ast`` (ADR-0009).

A single pure function, :func:`analyze_python`, maps a Python source text to a
list of :class:`TaintFinding` objects. No I/O, no state, no randomness, no new
dependency: the same source text always yields the same findings.

Taxonomy
--------

**Sources** — values an attacker controls (the analysis treats them as tainted):

1. The parameters of an MCP tool handler, i.e. a ``FunctionDef`` /
   ``AsyncFunctionDef`` decorated with ``*.tool`` (``@mcp.tool()``,
   ``@server.tool()``, bare ``@tool``, ...).
2. An attribute access on ``.params`` (``request.params["x"]``), matching the
   ``request.params`` pattern named in ADR-0009.

**Propagators** — constructs through which taint flows:

* assignment / augmented assignment (``x = tainted``, ``x += tainted``),
* f-strings / ``str.format`` / ``%``-format / ``+`` concatenation,
* ``join`` (and any call whose argument is tainted),
* indexing / attribute access (``tainted[0]``, ``tainted.attr``),
* container literals (``[tainted]``, ``{"k": tainted}``),
* function returns (a function whose return depends on its parameters or on a
  source is recorded as *returning taint*; callers are tainted),
* any unknown call with a tainted argument (over-approximation: an unrecognized
  function is assumed to preserve taint — recall over precision).

**Sinks** — where a tainted value is dangerous:

* shell (``FLOW-shell-injection``, error): ``os.system``, ``os.popen``,
  ``subprocess.run``/``call``/``check_call``/``check_output``/``Popen``/
  ``getoutput``/``getstatusoutput`` — first positional argument (the command).
* SQL (``FLOW-sql-injection``, error): a ``.execute``/``.executemany`` method
  call — first positional argument (the query). A parameterized call
  ``execute(query, params)`` keeps the tainted value out of the query and does
  not fire.
* code eval (``FLOW-code-eval``, warning): ``eval``/``exec``/``compile`` —
  first positional argument.

**Sanitizers** — a documented, versioned list of escaping functions. A tainted
value passed through one of these is considered clean; any other sanitizer is
treated as absent (favor recall over precision, per ADR-0009).

This is a conservative analysis: it reports *possible* taint. See ADR-0009 for
the accepted false-positive trade-off.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

# --- Taxonomy tables ---------------------------------------------------------

#: Shell sinks, matched by the fully-qualified callable name (``import os`` /
#: ``import subprocess`` style). Bare aliases (``from subprocess import run``)
#: are not resolved — a documented "to verify" limitation.
_SHELL_SINKS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)

#: Code-eval sinks: builtins, so matched by bare name.
_CODE_EVAL_SINKS = frozenset({"eval", "exec", "compile"})

#: SQL sinks, matched by method name (any ``.execute``/``.executemany``).
_SQL_SINKS = frozenset({"execute", "executemany"})

#: Documented, versioned sanitizer list (fully-qualified names). Unrecognized
#: sanitizers are treated as absent — recall over precision.
SANITIZERS = frozenset(
    {
        "shlex.quote",
        "html.escape",
        "markupsafe.escape",
        "sqlalchemy.sql.literal",
        "psycopg2.sql.Literal",
    }
)

_MESSAGES = {
    "FLOW-shell-injection": 'possibly tainted value reaches shell sink "{sink}"',
    "FLOW-sql-injection": 'possibly tainted value reaches SQL sink "{sink}"',
    "FLOW-code-eval": 'possibly tainted value reaches code-eval sink "{sink}"',
}


@dataclass(frozen=True)
class TaintFinding:
    """An internal result: a tainted value reaching a sink at a source location."""

    rule_id: str
    message: str
    line: int
    column: int  # 1-based
    end_line: int
    end_column: int  # 1-based
    snippet: str | None


# --- Helpers -----------------------------------------------------------------


def _dotted_name(node: ast.AST) -> str | None:
    """Resolve a callable to its dotted name (``subprocess.run``, ``eval``)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base is None:
            return node.attr
        return f"{base}.{node.attr}"
    return None


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = func.args
    names = [a.arg for a in args.posonlyargs + args.args]
    if args.vararg is not None:
        names.append(args.vararg.arg)
    names.extend(a.arg for a in args.kwonlyargs)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return names


def _decorator_name(dec: ast.expr) -> str | None:
    node = dec
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_tool_handler(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(_decorator_name(dec) == "tool" for dec in func.decorator_list)


def _collect_functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node
    return funcs


# --- Taint propagation -------------------------------------------------------


class _TaintAnalyzer:
    """Walks one function/module body, tracking tainted names and sink hits."""

    def __init__(self, returns_taint: frozenset[str]) -> None:
        self.returns_taint = returns_taint
        self.tainted: set[str] = set()
        self.findings: list[TaintFinding] = []
        self.lines: list[str] = []
        self.return_tainted = False

    # expression taint ------------------------------------------------------

    def _taint_expr(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Attribute):
            if node.attr == "params":
                return True  # source: X.params (request.params)
            return self._taint_expr(node.value)
        if isinstance(node, ast.Subscript):
            return self._taint_expr(node.value)
        if isinstance(node, ast.Starred):
            return self._taint_expr(node.value)
        if isinstance(node, ast.BinOp):
            return self._taint_expr(node.left) or self._taint_expr(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._taint_expr(v) for v in node.values)
        if isinstance(node, ast.IfExp):
            return self._taint_expr(node.body) or self._taint_expr(node.orelse)
        if isinstance(node, ast.NamedExpr):
            return self._taint_expr(node.value)
        if isinstance(node, ast.UnaryOp):
            return self._taint_expr(node.operand)
        if isinstance(node, ast.JoinedStr):
            return any(self._taint_expr(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._taint_expr(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._taint_expr(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(
                self._taint_expr(k) or self._taint_expr(v)
                for k, v in zip(node.keys, node.values)
            )
        if isinstance(node, ast.Compare):
            return False  # comparisons yield booleans; not a string injection
        if isinstance(node, ast.Lambda):
            return self._taint_expr(node.body)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._taint_expr(node.elt)
        if isinstance(node, ast.DictComp):
            return self._taint_expr(node.key) or self._taint_expr(node.value)
        if isinstance(node, ast.Call):
            return self._taint_call(node)
        return False

    def _taint_call(self, node: ast.Call) -> bool:
        dotted = _dotted_name(node.func)
        arg_taints = [self._taint_expr(a) for a in node.args]
        kw_taints = [self._taint_expr(k.value) for k in node.keywords]
        callee_tainted = self._taint_expr(node.func)

        if dotted in SANITIZERS:
            return False  # sanitized: result is clean

        self._check_sink(node, arg_taints)

        if any(arg_taints) or any(kw_taints) or callee_tainted:
            return True
        return dotted is not None and dotted in self.returns_taint

    def _check_sink(self, node: ast.Call, arg_taints: list[bool]) -> None:
        dotted = _dotted_name(node.func)
        if dotted is None:
            return
        if dotted in _CODE_EVAL_SINKS:
            if arg_taints and arg_taints[0]:
                self._record("FLOW-code-eval", dotted, node)
            return
        if dotted in _SHELL_SINKS:
            if arg_taints and arg_taints[0]:
                self._record("FLOW-shell-injection", dotted, node)
            return
        if (isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_SINKS
                and arg_taints and arg_taints[0]):
            self._record("FLOW-sql-injection", node.func.attr, node)

    def _record(self, rule_id: str, sink_name: str, node: ast.AST) -> None:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        end_line = getattr(node, "end_lineno", line)
        end_col = getattr(node, "end_col_offset", getattr(node, "col_offset", 0)) + 1
        snippet = self.lines[line - 1].rstrip("\n") if 0 < line <= len(self.lines) else None
        self.findings.append(
            TaintFinding(
                rule_id=rule_id,
                message=_MESSAGES[rule_id].format(sink=sink_name),
                line=line,
                column=col,
                end_line=end_line,
                end_column=end_col,
                snippet=snippet,
            )
        )

    # statements ------------------------------------------------------------

    def visit_body(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self._visit_stmt(stmt)

    def _visit_stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # analyzed separately (or out of scope)

        if isinstance(stmt, ast.Assign):
            if self._taint_expr(stmt.value):
                for target in stmt.targets:
                    self._assign_target(target)
            return

        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None and self._taint_expr(stmt.value):
                self._assign_target(stmt.target)
            return

        if isinstance(stmt, ast.AugAssign):
            if self._taint_expr(stmt.value):
                self._assign_target(stmt.target)
            return

        if isinstance(stmt, ast.Expr):
            self._taint_expr(stmt.value)
            return

        if isinstance(stmt, ast.Return):
            if stmt.value is not None and self._taint_expr(stmt.value):
                self.return_tainted = True
            return

        if isinstance(stmt, ast.If):
            self._taint_expr(stmt.test)
            self.visit_body(stmt.body)
            self.visit_body(stmt.orelse)
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            if self._taint_expr(stmt.iter):
                self._assign_target(stmt.target)
            self.visit_body(stmt.body)
            self.visit_body(stmt.orelse)
            return

        if isinstance(stmt, ast.While):
            self._taint_expr(stmt.test)
            self.visit_body(stmt.body)
            self.visit_body(stmt.orelse)
            return

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if (item.context_expr is not None and self._taint_expr(item.context_expr)
                        and item.optional_vars is not None):
                    self._assign_target(item.optional_vars)
            self.visit_body(stmt.body)
            return

        if isinstance(stmt, ast.Try):
            self.visit_body(stmt.body)
            for handler in stmt.handlers:
                self.visit_body(handler.body)
            self.visit_body(stmt.orelse)
            self.visit_body(stmt.finalbody)
            return

        if isinstance(stmt, ast.Assert):
            self._taint_expr(stmt.test)
            return

        # Import/ImportFrom/Pass/Global/Nonlocal/Delete/Raise/Break/Continue/
        # Match/TypeAlias and anything else: no taint effect.

    def _assign_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.tainted.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign_target(elt)


# --- Returns taint (fixed point) --------------------------------------------


def _compute_returns_taint(
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> frozenset[str]:
    """Names of functions whose return value can be tainted (params or source)."""
    returns: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, func in funcs.items():
            if name in returns:
                continue
            analyzer = _TaintAnalyzer(frozenset(returns))
            analyzer.tainted = set(_param_names(func))
            analyzer.visit_body(func.body)
            if analyzer.return_tainted:
                returns.add(name)
                changed = True
    return frozenset(returns)


# --- Public API --------------------------------------------------------------


def analyze_python(source: str) -> list[TaintFinding]:
    """Analyze Python source text and return sink findings (possibly tainted)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    lines = source.splitlines()
    funcs = _collect_functions(tree)
    returns_taint = _compute_returns_taint(funcs)
    tool_handlers = {name for name, f in funcs.items() if _is_tool_handler(f)}

    findings: list[TaintFinding] = []

    module_analyzer = _TaintAnalyzer(returns_taint)
    module_analyzer.lines = lines
    module_analyzer.visit_body(tree.body)
    findings.extend(module_analyzer.findings)

    for name in sorted(funcs):
        func = funcs[name]
        analyzer = _TaintAnalyzer(returns_taint)
        analyzer.lines = lines
        if name in tool_handlers:
            analyzer.tainted = set(_param_names(func))
        analyzer.visit_body(func.body)
        findings.extend(analyzer.findings)

    return findings
