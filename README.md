# mcp-security-scanner

Static security scanner for MCP servers and AI agent skills.

Detects excessive permissions (unrestricted shell, unsanitized SQL), risky
dependencies, and malicious patterns. Emits SARIF v2.1.0 for CI integration.

## Install

Requires Python 3.13 and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/A-Djihadi/mcp-security-scanner.git
cd mcp-security-scanner
uv sync
```

## Usage

```bash
# Scan a directory, write SARIF to a file (default format)
uv run mcpsec scan . --output results.sarif

# Human-readable output
uv run mcpsec scan . --format text

# Only error-level findings
uv run mcpsec scan . --severity error

# Only specific rules
uv run mcpsec scan . --rules MCP-shell-unrestricted,DEP-unpinned

# Exclude a rule
uv run mcpsec scan . --exclude-rule SKL-shell-execution
```

### Options

| Flag | Description |
|------|-------------|
| `--format sarif\|text` | Output format (default `sarif`). |
| `--output FILE` | Write output to `FILE` instead of stdout. |
| `--severity error\|warning\|note` | Only report findings at/above this severity. |
| `--rules IDS` | Comma-separated rule IDs to run; all others are disabled. |
| `--exclude-rule IDS` | Comma-separated rule IDs to disable. |
| `--fail-on error\|warning\|note` | Minimum severity that fails the scan (default `error`). |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; no findings at or above `--fail-on`. |
| 1 | Scan completed; one or more findings at or above `--fail-on`. |
| 2 | Internal error (bad args, unreadable path, parse error). |

## Rules

| Rule ID | Level | Detects |
|---------|-------|---------|
| `MCP-shell-unrestricted` | error | Server `command` is a shell interpreter (`sh`, `bash`, `zsh`, `powershell`, `pwsh`, `cmd`). |
| `MCP-allow-all` | error | `args` contains `--allow-all` / `--allow-everything` / `-A`. |
| `MCP-broad-network` | error | `--allow-net` with no host restriction. |
| `MCP-broad-filesystem` | warning | `--allow-read` / `--allow-write` at a root-level path (`/`, `~`, `C:\`, `C:/`) or with no path. |
| `SKL-shell-execution` | warning | Skill body invokes a shell with interpolated input (f-string / concatenation). |
| `SKL-remote-code-exec` | error | Skill body pipes remote content to a shell (`curl … \| sh`, `wget … \| bash`, `eval(fetch(…))`). |
| `SKL-obfuscated-command` | warning | Shell command decodes a `base64` payload (`base64 -d` / `--decode`). |
| `SKL-sql-concatenation` | error | SQL built by string concatenation/interpolation; parameterized `?` queries do not trigger. |
| `DEP-unpinned` | warning | A direct dependency whose version spec is unpinned (`*`, `latest`, `^`, `~`, empty). |

## CI integration

The scanner is deterministic and offline, so it fits a CI gate. Example GitHub
Actions step (no workflow file is shipped in this phase):

```yaml
- name: Install
  run: pipx install uv

- name: Scan for risky MCP configs and skills
  run: |
    uv run mcpsec scan . --output results.sarif || exit $?

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

The default `--fail-on error` makes `mcpsec` exit non-zero when an error-level
finding exists, which blocks the build.
