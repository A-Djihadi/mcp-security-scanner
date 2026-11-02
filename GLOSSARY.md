# mcp-security-scanner

Static security scanner for MCP servers and AI agent skills. Emits SARIF v2.1.0.

## Language

**Target**:
The normalized in-memory object a parser produces and a rule consumes; one of
`McpServer`, `Skill`, or `Dependency`.
_Avoid_: artifact, entry, record

**Finding**:
A single detected issue: a rule ID, severity, message, source location, and
fingerprint.
_Avoid_: result, violation, warning

**Rule**:
A deterministic static check that maps one `Target` to zero or more `Finding`s.
_Avoid_: check, pattern, policy

**Parser**:
An adapter that reads one file format and emits `Target[]`.
_Avoid_: reader, loader, importer

**RuleEngine**:
The module that applies enabled rules over targets and returns ordered findings.
_Avoid_: analyzer, engine

**Scan root**:
The directory `mcpsec scan` was pointed at; all reported paths are relative to it.
_Avoid_: project root, working dir

**Source location**:
File path plus 1-based line/column spans and an optional snippet.
_Avoid_: position, loc

**Fail-on threshold**:
The minimum severity that causes a non-zero exit code (default `error`).
_Avoid_: gate level
