---
title: Getting Started
description: Install opensecuritybot, configure a model, scaffold an engagement, and run your first triage and report.
---

opensecuritybot (command: `vapt`) is a local CLI that sits between your scanners and your report. It loads findings, drops anything outside the confirmed scope, then uses any OpenAI-compatible LLM to triage each finding, explain it, and compile a full VAPT report. Findings come from upstream tools (nmap, Nuclei, OWASP ZAP) or from the built-in [scan skills](../scan-skills/). The tool never exploits a target and never generates payloads.

## What it does

- Loads and normalizes findings: JSON arrays, `{ "findings": [...] }`, OWASP ZAP exports, Nuclei JSONL.
- Filters findings against `scope.json` before any LLM call. Out-of-scope findings are skipped, never sent.
- Triages each finding: true/false-positive call, adjusted severity, OWASP Top 10 (2021) mapping.
- Verifies programmatic replies: schema validation plus a CVE cross-check against the local cache (see [Verification](../verification/)).
- Compiles the full report — executive summary through remediation roadmap, sections 1–5 (see [Reports](../reports/)).
- Runs reviewed scan skills: allowlisted `nmap`/`nuclei`/`httpx` argv that you confirm step by step.
- Compares a baseline scan with a re-test to show what remediation actually fixed (`vapt diff`).

## What it does not do

- No exploitation, no payloads, no exploitability testing. The system prompt forbids it.
- No asset discovery of its own. Coverage equals what your scanners — or the scan skills — found.
- No blind trust in the model: every cited CVE is cross-checked, and anything unverifiable is flagged for manual review.
- No silent scope expansion. If `scope.json` is missing, unreadable or has no targets, `triage`, `report` and the session refuse to run. (`diff` only enforces scope when you pass `-s`.)

> Authorized engagements only. Findings outside `scope.json` never reach the model, and scanner content is treated as data, never as instructions. Confirming that you are authorized to test every entry in `scope.json` is your responsibility.

## Requirements

- Node.js >= 20 (`engines` in `package.json`).
- An LLM endpoint: any OpenAI-compatible chat-completions API (OpenAI, OpenRouter, Groq, Ollama, LM Studio, vLLM) or Anthropic's native messages API. Anthropic is auto-detected from the configured provider name, from an `anthropic.com` base URL, or from an `sk-ant-` key.
- The scanner binaries you intend to run via scan skills (`nmap`, `nuclei`, `httpx`) on `PATH`. Only `vapt scan` needs them.

## Install

Global install — gives you the `vapt` command:

```sh
npm install -g opensecuritybot
vapt setup
```

Without installing:

```sh
npx opensecuritybot setup
npx opensecuritybot triage -f findings.json -s scope.json
```

Inside a project, with the package added to it:

```sh
bun add opensecuritybot
bunx vapt setup
```

From a git checkout:

```sh
npm install
npm run build && npm link      # optional: global `vapt`
npm run dev -- setup           # or: vapt setup
```

## vapt setup

`vapt setup` walks through provider → API key (masked) → model and saves the choice to `~/.config/vapt/config.json`, owner-only (0600; the directory is created 0700). The model list is fetched live from the provider's `/models` endpoint; when that fails, a curated list is offered and you can still paste any model id.

| Provider | Base URL used |
| --- | --- |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Groq | `https://api.groq.com/openai/v1` |
| OpenAI | `https://api.openai.com/v1` |
| Meta Model API | `https://api.meta.ai/v1` |
| Anthropic | `https://api.anthropic.com/v1` |
| Custom (OpenAI-compatible) | you type it, e.g. `http://localhost:11434/v1` for Ollama |

Running `vapt`, `triage` or `report` with nothing configured starts the wizard automatically — but only on a TTY. Headless runs must use environment variables.

### Environment overrides

Environment variables take precedence over the config file. A `.env` file in the current working directory is loaded only when `VAPT_LOAD_DOTENV=1` is exported, because a `.env` in a directory you do not control can redirect where findings are sent.

| Variable | Default | Notes |
| --- | --- | --- |
| `VAPT_LLM_BASE_URL` | `https://api.openai.com/v1` | any OpenAI-compatible endpoint |
| `VAPT_LLM_MODEL` | — (required) | any model id your endpoint serves |
| `VAPT_LLM_API_KEY` | — | omit for local models |
| `VAPT_LLM_TIMEOUT_MS` | `120000` | per-request cap; streaming defaults to `300000` when unset |
| `VAPT_LLM_TEMPERATURE` | not sent | included only when set — newer Claude models reject values below 1 |
| `VAPT_CONFIG_DIR` | `~/.config/vapt` | overrides the config directory |
| `VAPT_NVD_API_KEY` | — | raises the NVD rate limit and shortens prefetch waits |
| `VAPT_NVD_MAX` | `25` | max CVEs prefetched per run; `0` disables prefetch |
| `VAPT_SKILLS_DIR` | bundled `skills/` | overrides the scan-skill directory for `vapt skills` and `vapt scan` |

The complete list, including report and retry tuning, is in the [CLI reference](../cli-reference/#environment-variables).

> Tip: for sensitive engagements, point the base URL at a local model (Ollama: `http://localhost:11434/v1`). Finding evidence is sent to whichever endpoint is configured.

## Scaffold an engagement: vapt init

```sh
mkdir acme && cd acme
vapt init
```

Writes `scope.json`, `cve-cache/` and `report/` into the current directory (`-d <dir>` targets another directory). It refuses to overwrite an existing `scope.json`; the two directories are created if missing. Next: edit the scope, drop scanner output at `findings.json`, then run `vapt`.

## scope.json

```json
{
  "engagement": "Acme Q4 external",
  "targets": ["acme.com", "*.api.acme.com", "10.10.0.0/24"],
  "exclude": ["pay.api.acme.com"],
  "notBefore": "2026-11-01T00:00:00Z",
  "notAfter": "2026-11-30T23:59:59Z"
}
```

- `targets` must be a non-empty array, or the tool refuses to run.
- Entries are plain strings or objects; object entries contribute the string values of `host`, `ip`, `url`, `domain`, `name`, `cidr` and `target`.
- Matching covers exact hosts, `*.wildcards` (base domain and subdomains), IPv4 CIDR and IPv6 CIDR ranges. Non-host strings are matched exactly.
- A bare host authorizes only itself: `acme.com` does not match `app.acme.com`. Use `*.acme.com` to include subdomains.
- `exclude` (optional) lists entries that are never in scope, even when a target matches. They win over `targets` everywhere: triage, report, diff and scan. Exclusions match whole hosts or CIDR ranges; an entry with a path is rejected.
- `notBefore` / `notAfter` (optional ISO dates) bound when `vapt scan` may run. Triage and reporting of already-collected data are not time-limited.
- Matching uses the host part of a target (`https://app.acme.com/x` matches `app.acme.com`), case-insensitively.
- This file is the security boundary. Keep it to targets covered by your authorization.

## findings.json

Accepted formats:

- A JSON array of objects.
- `{ "findings": [ ... ] }`.
- An OWASP ZAP JSON export (`site[].alerts[]`); severity is parsed from `riskdesc`/`risk`.
- Nuclei JSONL — one JSON object per line; `info.name` and `info.severity` are picked up.

Targets are read from `target`, `host`, `url`, `endpoint`, `matched_at`, `matchedAt`, `matched-at` or `asset`. Ids come from `id`, `findingId`, `template_id`, `template-id`, `_id`, `alertRef` or `pluginId`; entries without an id get `F-1`, `F-2`, … in a way that never collides with ids already present. Entries without a target are skipped with a note on stderr; duplicate ids are warned about. Bulk evidence under `raw` over 8 KB is replaced with a placeholder before anything reaches a prompt.

`triage` and `report` accept comma-separated paths for `-f`.

## First triage

```sh
vapt triage -f findings.json -s scope.json -c cve-cache
```

Streams one markdown triage per in-scope finding, severity-descending. Other forms:

```sh
vapt triage -f findings.json -s scope.json --id F-2      # one finding
vapt triage -f findings.json -s scope.json --json        # JSON array on stdout
```

CVE ids referenced by in-scope findings that are missing from `cve-cache/` are fetched from the NVD API before triage starts; caps and throttling are covered in [Verification](../verification/).

## First report

```sh
vapt report -f findings.json -s scope.json -c cve-cache -o report/
vapt report -f findings.json -s scope.json --html
```

Triages every finding (up to 4 calls in flight), then one synthesis call assembles sections 1–5. The Markdown is printed to stdout, then saved as `report/vapt-report-<timestamp>.md`; `--html` also saves a standalone HTML file. A `--out` that cannot be created fails before any LLM call. Details: [Reports](../reports/).

## Output contract

- **stdout** carries data: Markdown, JSON, listings. `--json` is always pipe-safe.
- **stderr** carries chrome: progress, spinners, skips, warnings, `saved:` confirmations, errors.
- Exit code is `1` when a finding fails triage, a scan step fails, a report save fails, or any unhandled error occurs. Partial results are still emitted.
- `vapt diff`, `vapt skills` and `vapt scan` need no LLM configuration — they run locally.

## Authorized use

This tool orchestrates assessment work; it does not grant permission to test anything. Before pointing it at a target, confirm you have written authorization and that every entry in `scope.json` is covered by it. The interactive session and every one-shot command apply the same scope filter, and scan skills refuse cloud metadata endpoints even if they are listed in scope.
