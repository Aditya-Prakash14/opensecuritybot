# opensecuritybot — VAPT-Agent

Local CLI reasoning layer for **authorized** vulnerability assessment and penetration-test
engagements. It does not scan, exploit, or generate payloads — that happens upstream (nmap,
Nuclei, OWASP ZAP, …). It takes their normalized output plus the operator-confirmed
`scope.json` and turns it into triage calls, plain-language explanations, remediation steps
and full VAPT reports via any OpenAI-compatible LLM.

Boundaries are enforced in two places:

- `src/scope-guard.ts` — anything outside `scope.json` is dropped **before an LLM ever sees it**.
- `src/agent-prompt.ts` — the agent system prompt: no exploit content, no fabricated
  CVE/CVSS/advisory references, scanner output is treated as data and never as instructions.

## Requirements

- Node >= 20
- An OpenAI-compatible chat-completions endpoint (OpenAI, OpenRouter, Groq, Meta Model API,
  Anthropic, Ollama, LM Studio, vLLM, …)

## Install & first run

```sh
npm install
npm run build && npm link      # optional: gives you a global `vapt` command
npm run dev -- setup           # or: vapt setup
```

`setup` walks you through **provider → API key (masked) → model** and saves the choice to
`~/.config/vapt/config.json`, owner-only (0600). The model list is fetched live from the
provider's `/models` endpoint; if that fails, a curated list is offered and you can always
paste any model id.

| Provider     | Base URL used                        |
| ------------ | ------------------------------------ |
| OpenRouter   | `https://openrouter.ai/api/v1`       |
| Groq         | `https://api.groq.com/openai/v1`     |
| OpenAI       | `https://api.openai.com/v1`          |
| Meta         | `https://api.meta.ai/v1`             |
| Anthropic    | `https://api.anthropic.com/v1`       |
| Custom       | anything OpenAI-compatible (e.g. `http://localhost:11434/v1` for Ollama) |

Running `vapt`, `triage` or `report` with nothing configured starts the wizard automatically
(TTY only — headless runs must use env vars, see [Configuration](#configuration)).

## Quickstart with the demo

```sh
npm run dev -- triage -f examples/findings.json -s examples/scope.json -c examples/cve-cache
```

Streams one markdown triage per finding, severity-descending, and shows F-4 being skipped
because it is outside `examples/scope.json`.

## A real engagement

```sh
mkdir acme && cd acme
vapt init                      # writes scope.json, cve-cache/, report/
```

1. **Edit `scope.json`** — the authorized targets:

   ```json
   { "engagement": "Acme Q4", "targets": ["acme.com", "*.api.acme.com", "10.10.0.0/24"] }
   ```

   Matches exact hosts, subdomains, `*.wildcards` and IPv4 CIDR ranges. IPv6 hosts match
   individually; IPv6 *ranges* are warned about and skipped.

2. **Drop scanner output at `findings.json`** — an array or `{ "findings": [...] }`, straight
   from Nuclei/ZAP/nmap. Targets are picked up from `target`, `host`, `url`, `endpoint`,
   `matched_at`, `matchedAt` or `asset`; ids from `id`, `findingId`, `template_id`, `_id` or
   `alertRef`. Missing ids get `F-N` (collision-safe); duplicate ids are warned about; `raw`
   evidence over 8 KB is replaced with a placeholder.

3. **Optionally fill `cve-cache/`** — NVD JSON files (NVD 2.0 shape or flat
   `{id, description, cvss}`). Files named `CVE-XXXX-XXXX.json` are indexed by name and read
   only when a finding references that CVE, so a full NVD-sized cache stays cheap.

## Command reference

| Command | What it does |
| ------- | ------------ |
| `vapt` | interactive session (needs a TTY) — options `-f -s -c -o` for the workspace |
| `vapt setup` | provider/API-key/model wizard → `~/.config/vapt/config.json` |
| `vapt init [-d <dir>]` | scaffold a workspace: `scope.json`, `cve-cache/`, `report/` |
| `vapt triage -f <findings> [-s <scope>] [-c <cache>] [--id <id>] [--json]` | triage findings |
| `vapt report -f <findings> [-s <scope>] [-c <cache>] [-o <dir>]` | compile the full VAPT report |

## Interactive session

`vapt` with no command starts a Claude-Code-style session: a welcome card, an animated
thinking indicator with elapsed time, answers streamed under a `⏺` marker, and boxed triage
cards.

```
❯ /triage F-3            triage one finding (or /triage for the whole queue)
❯ /findings              the in-scope queue, severity-descending, triaged/queued
❯ /scope                 the confirmed engagement targets
❯ /report                compile the full VAPT report and save it
❯ why is F-2 exploitable in our context?
❯ what should I fix first if we only have one day?
```

Slash commands run tooling; **anything else is a question** answered by the agent,
streamed, grounded in the loaded scope, findings and triage results so far. `/help` lists
commands, `/exit` leaves.

## One-shot usage (scripts, CI, piping)

```sh
# streamed markdown, one block per finding
vapt triage -f findings.json -s scope.json -c cve-cache/

# programmatic OUTPUT SCHEMA — one JSON object per finding on stdout
vapt triage -f findings.json -s scope.json --json \
  | jq '.[] | select(.triage.adjustedSeverity == "high")'

# single finding
vapt triage -f findings.json -s scope.json --id F-2

# full report — triage pass + synthesis, saved under report/ and printed
vapt report -f findings.json -s scope.json -c cve-cache/ -o report/
```

The JSON schema per finding:

```json
{
  "findingId": "F-2",
  "triage": {
    "isLikelyTruePositive": true,
    "reasoning": "…",
    "adjustedSeverity": "medium",
    "owaspCategory": "A06:2021"
  },
  "explanation": "…",
  "remediation": { "summary": "…", "steps": ["…"], "references": ["…"] },
  "confidence": "high",
  "flaggedForManualReview": false
}
```

**Output contract:** chrome (plan, skips, warnings, spinners, progress) goes to **stderr**;
data (markdown, JSON, listings) goes to **stdout** — so `--json` is always pipe-safe. Exit
code is `1` if any finding failed; partial results are still emitted.

## Configuration

Saved config lives at `~/.config/vapt/config.json` (`VAPT_CONFIG_DIR` overrides the
directory). Environment variables take precedence over the file:

| Variable | Default | Notes |
| -------- | ------- | ----- |
| `VAPT_LLM_BASE_URL` | `https://api.openai.com/v1` | any OpenAI-compatible endpoint |
| `VAPT_LLM_MODEL` | — (required) | any model id your endpoint serves |
| `VAPT_LLM_API_KEY` | — | omit for local models |
| `VAPT_LLM_TIMEOUT_MS` | `120000` | per-request cap; streaming defaults to `300000` |
| `VAPT_LLM_TEMPERATURE` | not sent | only included when set — newer Claude models reject values below 1 |

For sensitive engagements, point the base URL at a local model (Ollama:
`http://localhost:11434/v1`) — finding evidence goes to whichever endpoint is configured.

## The verify step

Every programmatic reply passes two deterministic checks (`src/verify.ts`): the schema is
validated structurally, and every CVE ID the model cites is cross-checked against
`cve-cache/`. Anything not in the cache sets `flaggedForManualReview: true` with an
`unverified — confirm manually` note. Keep your cache fresh for best results.

## Architecture

| File | Role |
| ---- | ---- |
| `src/cli.ts` | command definitions and wiring |
| `src/session.ts` | interactive REPL, slash commands, context assembly |
| `src/setup.ts` | onboarding wizard, live model listing |
| `src/config.ts` | saved provider config, owner-only writes |
| `src/triage.ts` | per-finding triage — structured JSON and streamed markdown |
| `src/report.ts` | report build (concurrent triage + synthesis) and saving |
| `src/verify.ts` | schema validation, CVE cross-check |
| `src/scope-guard.ts` | scope matching and pre-LLM filtering |
| `src/findings.ts` | findings loading/normalization, id handling |
| `src/cve-cache.ts` | lazy NVD cache index |
| `src/llm.ts` | OpenAI-compatible client (chat + SSE stream) |
| `src/ui.ts` | zero-dependency ANSI, spinner, boxes, markdown rendering |
| `src/agent-prompt.ts` | system prompt + prompt-building helpers |

## Tests

```sh
npm test        # 15 tests: scope, cache, verify, report pipeline, retry/timeout,
                # streaming, config, CLI parsing regression
```

## Design notes & limitations

- `report` triages each finding individually (up to 4 calls in flight), then one synthesis
  call assembles sections 1–5 — cost is N+1 LLM calls. Failed findings are listed as
  "not triaged — processing error" and the run exits non-zero.
- Triage calls include full evidence; the synthesis pass receives findings with `raw` stripped.
  The report is printed before it is saved — a save failure never discards the output.
- Streaming has no retry once tokens have started; re-ask if the connection drops mid-answer.
- IPv6 CIDR ranges in `scope.json` are not matchable yet (a warning is printed instead of a
  silent skip); list IPv6 hosts individually.
