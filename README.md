# mcp-security-scanner

[![CI](https://github.com/A-Djihadi/mcp-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/A-Djihadi/mcp-security-scanner/actions/workflows/ci.yml)

Static security scanner for MCP servers and AI agent skills.

Detects excessive permissions (unrestricted shell, unsanitized SQL), risky
dependencies, and malicious patterns. Emits SARIF v2.1.0 for CI integration.

## Install

Requires Python 3.13.

Install the published package from PyPI:

```bash
pip install mcp-skill-scanner
```

Opt into semantic detection with the `[semantic]` extra:

```bash
pip install mcp-skill-scanner[semantic]
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

# Skip paths (globs, repeatable), e.g. to scan a repo that contains test fixtures
uv run mcpsec scan . --exclude tests/fixtures

# Network-backed rules (OSV.dev, PyPI/npm, reachability) -- opt-in
uv run mcpsec scan . --online
```

### Options

| Flag | Description |
|------|-------------|
| `--format sarif\|text` | Output format (default `sarif`). |
| `--output FILE` | Write output to `FILE` instead of stdout. |
| `--severity error\|warning\|note` | Only report findings at/above this severity. |
| `--rules IDS` | Comma-separated rule IDs to run; all others are disabled. |
| `--exclude-rule IDS` | Comma-separated rule IDs to disable. |
| `--exclude GLOB` | Skip paths matching `GLOB` (relative to the scan root, matches parent directories too; repeatable). |
| `--online` | Enable network-backed rules (`DEP-known-vulnerability`, `DEP-outdated`, `DEP-unknown`, `MCP-unreachable`). Only `http(s)` is fetched; private, loopback and link-local addresses are never probed. |
| `--fail-on error\|warning\|note` | Minimum severity that fails the scan (default `error`). |
| `--semantic` | Enable semantic malicious-intent detection via the local embedding model (requires the `[semantic]` extra). |

### Semantic detection (optional)

`--semantic` opts into embedding-based malicious-intent detection for skills
(`SKL-semantic-malicious`). It is **off by default**: the base install stays
PyYAML-only, and a default scan never loads the model runtime.

```bash
# Opt into the heavier install once:
uv sync --extra semantic   # or: pip install mcp-skill-scanner[semantic]

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
| `MCP-shell-unrestricted` | error | Server `command` is a shell interpreter (`sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, `csh`, `powershell`, `pwsh`, `cmd`…), including behind a launcher (`env bash`, `sudo sh`). |
| `MCP-allow-all` | error | `args` contains `--allow-all` / `--allow-everything` / `-A`. |
| `MCP-broad-network` | error | `--allow-net` with no host restriction (bare flag or empty value). |
| `MCP-inline-code` | warning | Interpreter runs code passed on the command line (`python -c`, `node -e`, `ruby -e`, `perl -e`, `php -r`). |
| `MCP-insecure-transport` | error | Remote MCP server uses plaintext `http://`. |
| `MCP-header-secret` | warning | A secret is stored inline in a remote server's `headers`. |
| `MCP-remote-no-auth` | note | Remote MCP server has no auth-bearing header. |
| `MCP-parse-ambiguous` | note | Server command cannot be statically resolved from the config. |
| `MCP-unreachable` | note | Remote endpoint refused the connection (`--online`). |
| `FLOW-shell-injection` | error | Tainted MCP tool input reaches a shell execution sink (Python taint analysis). |
| `FLOW-sql-injection` | error | Tainted input reaches a SQL query sink. |
| `FLOW-code-eval` | warning | Tainted input reaches `eval` / `exec` / `compile`. |
| `MCP-broad-filesystem` | warning | `--allow-read` / `--allow-write` at a root-level path (`/`, `~`, `C:\`, `C:/`) or with no path. |
| `SKL-shell-execution` | warning | Skill body invokes a shell with interpolated input (f-string / concatenation). |
| `SKL-remote-code-exec` | error | Skill body pipes remote content to a shell (`curl … \| sh`, `wget … \| bash`, `eval(fetch(…))`). |
| `SKL-obfuscated-command` | warning | Shell command decodes a `base64` payload (`base64 -d` / `--decode`). |
| `SKL-sql-concatenation` | error | SQL built by string concatenation/interpolation; parameterized `?` queries do not trigger. |
| `DEP-unpinned` | warning | A direct dependency whose version spec is unpinned (`*`, `latest`, `^`, `~`, empty). |
| `DEP-known-vulnerability` | error | Declared version has a known vulnerability in OSV.dev (`--online`). |
| `DEP-outdated` | warning | Declared version is behind the latest published one (`--online`). |
| `DEP-unknown` | warning | Name closely resembles a popular package, a typosquat signal (`--online`). |
| `SKL-semantic-malicious` | warning | Skill prose is semantically similar to a known-malicious reference (opt-in via `--semantic`). |

## LLM triage (optional)

`mcpsec triage` runs the same scan, then explains each finding and proposes a fix with a
**local** model (Ollama). It is advisory: findings, levels and the exit code are never
changed by the model ([ADR-0011](docs/adr/0011-llm-triage-advisory.md)).

```bash
uv sync --extra agent                 # LangGraph + Langfuse
ollama pull qwen2.5-coder:3b
uv run mcpsec triage . --exclude tests/fixtures                 # text report
uv run mcpsec triage . --format sarif --output triage.sarif     # SARIF + properties.triage
```

How it works: a LangGraph graph fans out one branch per finding (`Send`); each branch loads
the file excerpt, asks the model for `explanation`, `fix` and `evidence`, and keeps the answer
only if the evidence line really exists in the file (one stricter retry, then a rule-based
explanation). The excerpt is passed as untrusted data, so instructions hidden in a scanned
skill cannot change the result. Set `LANGFUSE_BASE_URL`, `LANGFUSE_PUBLIC_KEY` and
`LANGFUSE_SECRET_KEY` to trace every node, model call (tokens) and `grounded` score in a
self-hosted Langfuse.

## CI integration

The scanner is deterministic and offline, so it fits a CI gate. This repository
ships its own GitHub Actions workflow —
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) — which lints (ruff), runs the
test suite, **scans this repository with mcpsec itself** and uploads the SARIF to the
Security tab, and runs a gitleaks secrets scan on every push and pull request.

To gate another project on `mcpsec` (actions pinned by commit SHA, as in this repo):

```yaml
jobs:
  mcpsec:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write          # required to upload SARIF
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2 # v10.3.3
      - name: Scan for risky MCP configs and skills
        run: uvx --from git+https://github.com/A-Djihadi/mcp-security-scanner mcpsec scan . --output results.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with:
          sarif_file: results.sarif
```

`uvx --from git+…` installs mcpsec in an isolated environment (pin it with `@<tag or sha>`
in real use); `uv run mcpsec` only works inside this repository.

The default `--fail-on error` makes `mcpsec` exit non-zero when an error-level
finding exists, which blocks the build.

## License

[MIT](LICENSE) © 2026 Djihadi Ahamdy.
