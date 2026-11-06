# mcp-security-scanner

[![CI](https://github.com/A-Djihadi/mcp-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/A-Djihadi/mcp-security-scanner/actions/workflows/ci.yml)

Static security scanner for MCP servers and AI agent skills.

Detects excessive permissions (unrestricted shell, unsanitized SQL), risky
dependencies, and malicious patterns. Emits SARIF v2.1.0 for CI integration.

## Install

Requires Python 3.13.

Install the published package from PyPI:

```bash
pip install mcpsec-scan
```

Opt into semantic detection with the `[semantic]` extra:

```bash
pip install mcpsec-scan[semantic]
```

Or install from source with [`uv`](https://docs.astral.sh/uv/):

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
| `--semantic` | Enable semantic malicious-intent detection via the local embedding model (requires the `[semantic]` extra). |

### Semantic detection (optional)

`--semantic` opts into embedding-based malicious-intent detection for skills
(`SKL-semantic-malicious`). It is **off by default**: the base install stays
PyYAML-only, and a default scan never loads the model runtime.

```bash
# Opt into the heavier install once:
uv sync --extra semantic   # or: pip install mcpsec-scan[semantic]

# Then scan with semantic detection enabled:
uv run mcpsec scan . --semantic
```

The default embedder is a small, CPU-only ONNX sentence-transformer:

- **Model:** `all-MiniLM-L6-v2` (ONNX export `Xenova/all-MiniLM-L6-v2`), Apache-2.0.
- **Pinned revision:** `751bff37182d3f1213fa05d7196b954e230abad9` (files verified by SHA-256).
- **Corpus:** a curated, versioned set of malicious-intent anchors
  (`src/mcpsec/corpus.py`, version `1`); the model revision and corpus version
  are recorded on every `SKL-semantic-malicious` finding for reproducibility.

**To verify:** the similarity threshold (default `0.85`) and the corpus anchor
coverage are calibrated against synthetic probes, not a production corpus; they
should be re-tuned against real-world skill data before relying on this rule as
a CI gate.

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
| `SKL-semantic-malicious` | warning | Skill prose is semantically similar to a known-malicious reference (opt-in via `--semantic`). |

## CI integration

The scanner is deterministic and offline, so it fits a CI gate. This repository
ships its own GitHub Actions workflow —
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) — which runs the test
suite (`uv run pytest`) and a gitleaks secrets scan on every push and pull
request.

To gate another project on `mcpsec`, run the same command the workflow runs and
upload the SARIF report:

```yaml
- name: Install uv
  uses: astral-sh/setup-uv@v10

- name: Scan for risky MCP configs and skills
  run: uv run mcpsec scan . --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

The default `--fail-on error` makes `mcpsec` exit non-zero when an error-level
finding exists, which blocks the build.

## License

[MIT](LICENSE) © 2026 Djihadi Ahamdy.
