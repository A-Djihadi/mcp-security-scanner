"""``smithery.yaml`` parser.

The `smithery.yaml <https://smithery.ai/docs/config>`_ file describes how to
start an MCP server on Smithery. The shape is grounded against the archived
Smithery docs and many real repositories:

* ``startCommand.type`` — ``stdio`` is the only value the docs document
  ("standard I/O based MCP server"). Any other value is mapped to
  ``transport == "remote"`` and the raw value is preserved on the target;
  the exact accepted remote values are **to verify** (never a silent guess).
* ``configSchema`` — a JSON Schema for the server's configuration options;
  its ``required`` keys are captured on the target (``config_required``).
* ``commandFunction`` — a JS function ``(config) => ({command, args, env})``,
  written as a YAML block scalar. Only a fully-literal return is extracted; a
  dynamic/conditional return yields ``command is None`` plus a
  ``MCP-parse-ambiguous`` note (see ``mcpsec.rules.parsing``).
* ``exampleConfig`` — present in the schema but not parsed into the target.

``configSchema``/``commandFunction`` appear both at top level and nested under
``startCommand`` across real repositories; both placements are tolerated
(top-level takes precedence). The server ``name`` is not part of the schema, so
the parser derives it from the enclosing directory (to verify).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..errors import ParseError
from ..model import SourceLocation, Target, TargetKind
from ._common import normalize_path


class SmitheryYamlParser:
    """Parse a ``smithery.yaml`` into a single ``McpServer`` target."""

    def parse(self, path: Path) -> list[Target]:
        text = path.read_text(encoding="utf-8")
        try:
            root = yaml.compose(text, Loader=yaml.SafeLoader)
        except yaml.YAMLError as exc:
            raise ParseError(f"invalid smithery.yaml: {exc}") from exc

        if not isinstance(root, yaml.MappingNode):
            return []

        top = _mapping(root)
        start_command = top.get("startCommand")
        if not isinstance(start_command, yaml.MappingNode):
            return []

        nested = _mapping(start_command)

        def resolve(key: str) -> yaml.Node | None:
            # Real files put configSchema/commandFunction at top level or nested
            # under startCommand; tolerate both, top-level first.
            return top.get(key) if key in top else nested.get(key)

        raw_type = _scalar(nested.get("type"))
        transport = "stdio" if (raw_type is None or raw_type == "stdio") else "remote"

        config_required, required_locs = _config_required(
            resolve("configSchema"), path
        )
        command, args, env, ambiguous, reason, fn_loc = _command(
            resolve("commandFunction"), transport, path
        )

        field_locations: dict = {"config_required": required_locs}
        if fn_loc is not None:
            field_locations["commandFunction"] = fn_loc
        if command is not None:
            field_locations["command"] = fn_loc
        if args:
            field_locations["args"] = tuple(fn_loc for _ in args)
        if env:
            field_locations["env"] = {key: fn_loc for key in env}

        payload = {
            "command": command,
            "args": args,
            "env": env,
            "cwd": None,
            "transport": transport,
            "url": None,
            "start_command_type": raw_type,
            "config_required": config_required,
            "parse_ambiguous": ambiguous,
            "parse_note": reason,
        }

        normalized = normalize_path(path)
        return [
            Target(
                kind=TargetKind.MCP_SERVER,
                name=path.parent.name,
                location=SourceLocation(
                    path=normalized, start_line=1, start_column=1
                ),
                payload=payload,
                field_locations=field_locations,
            )
        ]


# --- YAML node helpers -------------------------------------------------------


def _mapping(node: yaml.Node) -> dict[str, yaml.Node]:
    if not isinstance(node, yaml.MappingNode):
        return {}
    result: dict[str, yaml.Node] = {}
    for key_node, value_node in node.value:
        key = _scalar(key_node)
        if key is not None:
            result[key] = value_node
    return result


def _scalar(node: yaml.Node | None) -> str | None:
    if isinstance(node, yaml.ScalarNode):
        return node.value
    return None


def _node_location(node: yaml.Node, path: Path) -> SourceLocation:
    mark = node.start_mark
    snippet = node.value if isinstance(node, yaml.ScalarNode) else None
    return SourceLocation(
        path=normalize_path(path),
        start_line=mark.line + 1,
        start_column=mark.column + 1,
        snippet=snippet,
    )


def _config_required(
    schema_node: yaml.Node | None, path: Path
) -> tuple[list[str], dict[str, SourceLocation]]:
    if not isinstance(schema_node, yaml.MappingNode):
        return [], {}
    schema = _mapping(schema_node)
    required = schema.get("required")
    if not isinstance(required, yaml.SequenceNode):
        return [], {}
    keys: list[str] = []
    locs: dict[str, SourceLocation] = {}
    for item in required.value:
        key = _scalar(item)
        if key is None:
            continue
        keys.append(key)
        locs[key] = _node_location(item, path)
    return keys, locs


def _command(
    fn_node: yaml.Node | None,
    transport: str,
    path: Path,
) -> tuple[str | None, list[str], dict[str, str], bool, str | None, SourceLocation | None]:
    loc = _node_location(fn_node, path) if fn_node is not None else None
    if transport == "remote":
        # Remote servers are reached over the network; there is no local command
        # to extract, so this is not "ambiguous".
        return None, [], {}, False, None, loc

    if fn_node is None:
        return None, [], {}, True, "no commandFunction for a stdio server", loc

    fn_text = _scalar(fn_node)
    if fn_text is None:
        return None, [], {}, True, "commandFunction is not a string", loc

    result = _extract_command_function(fn_text)
    return result.command, result.args, result.env, result.ambiguous, result.reason, loc


# --- commandFunction JS literal extraction -----------------------------------


@dataclass
class _CommandResult:
    command: str | None
    args: list[str]
    env: dict[str, str]
    ambiguous: bool
    reason: str | None


_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_RETURN = re.compile(r"\breturn\b")
_CONDITIONAL_WORDS = frozenset({"if", "switch", "for", "while", "do"})


def _extract_command_function(fn: str) -> _CommandResult:
    body = _arrow_body(fn)
    if body is None:
        return _CommandResult(
            None, [], {}, True, "no arrow function (=>) found in commandFunction"
        )
    expr = _return_expression(body)
    if expr is None:
        return _CommandResult(
            None, [], {}, True, "commandFunction return is not statically extractable"
        )
    members = _parse_object_literal(expr)
    if members is None:
        return _CommandResult(
            None, [], {}, True, "commandFunction return is not a literal object"
        )

    command_node = members.get("command")
    if command_node is None or command_node[0] != "string":
        return _CommandResult(
            None, [], {}, True, "command is missing or not a string literal"
        )

    args: list[str] = []
    args_node = members.get("args")
    if args_node is not None:
        if args_node[0] != "array":
            return _CommandResult(None, [], {}, True, "args is not a literal array")
        args = args_node[1]

    env: dict[str, str] = {}
    env_node = members.get("env")
    if env_node is not None:
        if env_node[0] != "object":
            return _CommandResult(None, [], {}, True, "env is not a literal object")
        env = env_node[1]

    return _CommandResult(command_node[1], args, env, False, None)


def _arrow_body(fn: str) -> str | None:
    idx = fn.find("=>")
    if idx == -1:
        return None
    return fn[idx + 2 :]


def _return_expression(body: str) -> str | None:
    body = body.strip()
    if not body:
        return None
    if body.startswith("("):
        return _paren_content(body)
    if body.startswith("{"):
        if _has_conditional(body):
            return None
        returns = _return_statements(body)
        if len(returns) != 1:
            return None
        return returns[0]
    return None


def _paren_content(s: str) -> str | None:
    depth = 0
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                if i != len(s) - 1:
                    return None
                return s[1:i]
    return None


def _return_statements(body: str) -> list[str]:
    results: list[str] = []
    i = 0
    while True:
        match = _RETURN.search(body, i)
        if match is None:
            break
        expr, end = _read_until_terminator(body, match.end())
        results.append(expr)
        i = end
    return results


def _read_until_terminator(s: str, i: int) -> tuple[str, int]:
    i = _skip_ws(s, i)
    out: list[str] = []
    depth = 0
    while i < len(s):
        ch = s[i]
        if ch in ("'", '"'):
            val = _read_string(s, i)
            if val is None:
                return "".join(out), i
            out.append(s[i : val[1]])
            i = val[1]
            continue
        if ch == "{":
            depth += 1
            out.append(ch)
            i += 1
            continue
        if ch == "}":
            if depth == 0:
                return "".join(out), i
            depth -= 1
            out.append(ch)
            i += 1
            continue
        if ch == ";" and depth == 0:
            return "".join(out), i + 1
        out.append(ch)
        i += 1
    return "".join(out), i


def _has_conditional(body: str) -> bool:
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch in ("'", '"'):
            val = _read_string(body, i)
            if val is None:
                return False
            i = val[1]
            continue
        if ch == "?":
            return True
        if ch in "&|" and i + 1 < n and body[i + 1] == ch:
            return True
        if ch.isalpha() or ch in "_$":
            j = i
            while j < n and (body[j].isalnum() or body[j] in "_$"):
                j += 1
            if body[i:j] in _CONDITIONAL_WORDS:
                return True
            i = j
            continue
        i += 1
    return False


def _parse_object_literal(expr: str) -> dict | None:
    expr = expr.strip()
    if not expr.startswith("{"):
        return None
    members: dict = {}
    i = _skip_ws(expr, 1)
    n = len(expr)
    while True:
        if i >= n:
            return None
        if expr[i] == "}":
            return members
        key, i = _read_key(expr, i)
        if key is None:
            return None
        i = _skip_ws(expr, i)
        if i >= n or expr[i] != ":":
            return None
        value, i = _read_value(expr, i + 1)
        if value is None:
            return None
        members[key] = value
        i = _skip_ws(expr, i)
        if i < n and expr[i] == ",":
            i += 1
            continue
        if i < n and expr[i] == "}":
            return members
        return None


def _read_value(s: str, i: int):
    i = _skip_ws(s, i)
    if i >= len(s):
        return None, i
    ch = s[i]
    if ch in ("'", '"'):
        val = _read_string(s, i)
        if val is None:
            return None, i
        return ("string", val[0]), val[1]
    if ch == "[":
        return _read_array(s, i)
    if ch == "{":
        return _read_object(s, i)
    return None, i


def _read_array(s: str, i: int):
    i = _skip_ws(s, i + 1)
    items: list[str] = []
    while True:
        i = _skip_ws(s, i)
        if i >= len(s):
            return None, i
        if s[i] == "]":
            return ("array", items), i + 1
        val = _read_string(s, i)
        if val is None:
            return None, i
        items.append(val[0])
        i = _skip_ws(s, val[1])
        if i < len(s) and s[i] == ",":
            i += 1
            continue
        if i < len(s) and s[i] == "]":
            return ("array", items), i + 1
        return None, i


def _read_object(s: str, i: int):
    i = _skip_ws(s, i + 1)
    result: dict[str, str] = {}
    while True:
        i = _skip_ws(s, i)
        if i >= len(s):
            return None, i
        if s[i] == "}":
            return ("object", result), i + 1
        key, i = _read_key(s, i)
        if key is None:
            return None, i
        i = _skip_ws(s, i)
        if i >= len(s) or s[i] != ":":
            return None, i
        val, i = _read_value(s, i + 1)
        if val is None or val[0] != "string":
            return None, i
        value = val[1]
        if not isinstance(value, str):
            return None, i
        result[key] = value
        i = _skip_ws(s, i)
        if i < len(s) and s[i] == ",":
            i += 1
            continue
        if i < len(s) and s[i] == "}":
            return ("object", result), i + 1
        return None, i


def _read_key(s: str, i: int) -> tuple[str, int] | tuple[None, int]:
    i = _skip_ws(s, i)
    if i >= len(s):
        return None, i
    if s[i] in ("'", '"'):
        val = _read_string(s, i)
        if val is None:
            return None, i
        return val[0], val[1]
    match = _IDENT.match(s, i)
    if match:
        return match.group(), match.end()
    return None, i


def _read_string(s: str, i: int) -> tuple[str, int] | None:
    quote = s[i]
    i += 1
    out: list[str] = []
    while i < len(s):
        ch = s[i]
        if ch == "\\":
            if i + 1 < len(s):
                nxt = s[i + 1]
                if nxt in ("'", '"', "\\"):
                    out.append(nxt)
                    i += 2
                    continue
                out.append("\\")
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            i += 1
            continue
        if ch == quote:
            return "".join(out), i + 1
        out.append(ch)
        i += 1
    return None


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t\r\n":
        i += 1
    return i
