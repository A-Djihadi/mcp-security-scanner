# Security policy

## Reporting a vulnerability

**Do not disclose security issues in a public issue or pull request.**

Use GitHub private vulnerability reporting: **Security** tab > **Report a vulnerability**.

Target timeline: acknowledgement within 7 days, a fix or mitigation plan within 30 days.
Once fixed, a GitHub Security Advisory (and a CVE when relevant) is published.

## Supported versions

Early development: only `main` receives fixes.

## What mcpsec guarantees (and does not)

- `mcpsec scan` is **static and offline by default**: it reads configuration, skill and
  source files and never executes them. `--online` is opt-in: it only fetches `http(s)`
  URLs, caps response sizes, and never probes loopback, private or link-local addresses
  taken from a scanned file.
- Detection is **signature-based** (see the rule table in the README). A clean scan is not a
  proof of safety: obfuscated or novel patterns can be missed. Please report false negatives
  through the private channel above when they reveal a bypass.
- `mcpsec triage` (optional `agent` extra) sends finding context to a **local** model
  (Ollama). Its output is advisory only: it never changes a finding, its level or the exit
  code, and scanned files are treated as untrusted input (prompt injection).
