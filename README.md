# opensecuritybot — VAPT-Agent

Local CLI reasoning layer for **authorized** vulnerability assessment and penetration test
engagements. It does not scan, exploit, or generate payloads — that happens upstream
(nmap, Nuclei, ZAP, …). It takes their normalized output (`findings[]`) plus the confirmed
`scope.json` and produces triage calls, plain-language explanations, remediation steps and
full VAPT reports via an OpenAI-compatible LLM.

Boundaries are enforced in two places:

- `src/scope-guard.ts` — anything outside `scope.json` is dropped before an LLM ever sees it.
- `src/agent-prompt.ts` — the agent system prompt: no exploit content, no fabricated
  CVE/CVSS/advisory references, scanner output is data and never instructions.

## Requirements

- Node >= 20
- An OpenAI-compatible chat-completions endpoint (OpenAI, OpenRouter, Ollama, vLLM, LM Studio, …)

## Setup

```sh
npm install

export VAPT_LLM_BASE_URL=https://api.openai.com/v1   # default; use http://localhost:11434/v1 for Ollama
export VAPT_LLM_MODEL=gpt-4o-mini                    # any model your endpoint serves
export VAPT_LLM_API_KEY=sk-...                       # omit for local models
export VAPT_LLM_TIMEOUT_MS=120000                    # optional per-request timeout (default 120000)
```

## Usage

Examples use the bundled demo (`-s examples/scope.json -c examples/cve-cache`); swap in your
own engagement's files when running for real.

```sh
# development (no build step)
npm run dev -- triage -f examples/findings.json -s examples/scope.json -c examples/cve-cache

# --json for the programmatic OUTPUT SCHEMA (one object per finding on stdout)
npm run dev -- triage -f examples/findings.json -s examples/scope.json -c examples/cve-cache --json | jq '.[0].triage'

# single finding
npm run dev -- triage -f examples/findings.json -s examples/scope.json -c examples/cve-cache --id F-2

# full report — per-finding triage first, then a synthesis pass; saved to report/ and printed to stdout
npm run dev -- report -f examples/findings.json -s examples/scope.json -c examples/cve-cache -o report/

# production
npm run build && node dist/cli.js triage --help
```

Logs (plan, skipped findings, failures) go to **stderr**; data (markdown or JSON) goes to
**stdout**, so `--json` output is always pipe-safe. Exit code is 1 if any finding failed
to triage — partial results are still emitted.

## Workspace layout

| Path          | Role                                                                |
| ------------- | ------------------------------------------------------------------- |
| `scope.json`  | confirmed engagement scope — **required**, the run refuses without it |
| `findings`    | scanner output: array or `{ "findings": [...] }`; needs `id`/`target` or common aliases (`host`, `url`, `matched_at`, …) |
| `cve-cache/`  | optional NVD CVE JSON files (NVD 2.0 shape or flat `{id, description, cvss}`) |
| `report/`     | generated reports (gitignored)                                      |

Findings whose `target` is not in scope are skipped with a stderr note, never sent to the
model. `raw`/`evidence` blobs larger than 8 KB are replaced with a size placeholder. Cache
files named `CVE-XXXX-XXXX.json` are indexed by name and read only when a finding references
that CVE, so a full NVD-sized cache stays cheap. IPv6 ranges in `scope.json` cannot be
matched yet — a warning is printed; list IPv6 hosts individually.

## The verify step

Beyond smoke tests, `src/verify.ts` does two deterministic checks on every programmatic
reply: the schema is validated structurally, and every CVE ID the model cites is
cross-checked against `cve-cache/`. Anything not in the cache is marked
`flaggedForManualReview: true` with an `unverified — confirm manually` note. Keep your
cache fresh for best results.

## Tests

```sh
npm test
```

## Design notes

- `report` mode triages each finding individually — up to four calls in flight — then one
  synthesis call assembles sections 1–5. Cost is N+1 LLM calls; findings whose triage failed
  are flagged as "not triaged — processing error" in the report and the run exits non-zero.
- Triage calls include the full finding, evidence included; the synthesis pass receives
  findings with `raw` stripped. For sensitive engagements, point `VAPT_LLM_BASE_URL` at a
  local model.
