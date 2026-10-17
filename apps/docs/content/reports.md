---
title: Reports
description: How `vapt report` builds sections 1–5, where output lands, and how to verify remediation with `vapt diff`.
---

`vapt report` produces the deliverable: one Markdown document covering executive summary through prioritized remediation roadmap, optionally saved as standalone HTML. It runs the same triage pass as `vapt triage`, then one synthesis call that assembles everything.

## Cost and flow

- N findings = N triage calls + 1 synthesis call. Triage runs with up to 4 calls in flight (`TRIAGE_CONCURRENCY`), and results keep severity order. The synthesis call receives all triage results in a single prompt.
- The synthesis prompt is told to use the pre-computed triage results as the substance of section 3 and not re-triage.
- A finding whose triage fails is not dropped silently: it is listed under its severity as "not triaged — processing error", the failure list is printed on stderr, and the exit code is `1`. If every finding fails, no report is produced and the command exits `1`.
- The `--out` directory is created before any LLM call, so a bad output path costs nothing.

Sections, from the report prompt:

1. Executive Summary — business language, severity counts, overall risk posture.
2. Scope & Methodology — the confirmed scope, plus the tools that actually ran (see below).
3. Findings — grouped by severity, each with the triage call, explanation and remediation from the triage pass.
4. OWASP Top 10 coverage matrix.
5. Remediation Roadmap — prioritized by severity × effort.

## Evidence handling

Triage calls receive the full finding, evidence included. The synthesis pass receives findings with `raw` stripped, so bulk scanner evidence does not ride into the report prompt. The report prompt also requires: Markdown only, no exploit payloads, no raw traffic, no credentials — the report should state that evidence is held in a separate, access-controlled evidence log. Evidence over 8 KB was already replaced with a placeholder when the findings file was loaded.

## Methodology from the execution ledger

If a ledger exists at `<out>/scan-ledger.jsonl`, its steps are folded into the synthesis prompt with instructions to reproduce them verbatim in section 2 (Scope & Methodology). One bullet per step, in file order, capped at 50 — beyond that a single "… and N more step(s)" line. Each bullet carries the timestamp, skill, target, full argv, exit code, duration, output size and a short SHA-256 prefix.

`vapt scan` writes `report/scan-ledger.jsonl` by default, and `vapt report -o report` reads the same path. If you changed either `scan --ledger` or `report -o`, keep them aligned — the ledger is read relative to the report output directory.

## Output files

- `vapt-report-<YYYYMMDDTHHMMSS>.md` — always written, under `-o <dir>` (default `./report`).
- `vapt-report-<YYYYMMDDTHHMMSS>.html` — with `--html`: a standalone responsive HTML document. The title uses the `engagement` field from `scope.json` when present, otherwise "VAPT Assessment Report".
- The Markdown is printed to **stdout before saving**. A save failure prints a warning, keeps the printed report, and exits `1` — a disk problem never discards the report.
- `--json` emits `{ "scope", "findingsCount", "markdown", "failures" }` to stdout instead of printing the Markdown. Files are still saved in this mode.
- `--quiet` suppresses progress on stderr; the report body still goes to stdout.

## Failure handling and exit codes

| Situation | stdout | stderr | Exit |
| --- | --- | --- | --- |
| Clean run | Markdown (or JSON payload) | progress, `saved:` lines | 0 |
| Some findings failed triage | partial report | failure list | 1 |
| Every finding failed triage | nothing | error | 1 |
| Save failed after printing | report printed above | warning | 1 |
| `--out` not writable | nothing | error | 1 (before any LLM call) |
| LLM/config error | nothing | error | 1 |

## The token-size guard

The synthesis prompt is one call. Its size is estimated at roughly 4 characters per token; when the estimate exceeds `VAPT_REPORT_MAX_PROMPT_TOKENS` (default `120000`) a warning is logged — the call still proceeds. Set it to `0` to disable the check. For large engagements, raise the limit for a large-context model or split the engagement into batches.

## Remediation deltas: vapt diff

```sh
vapt diff -b baseline.json -c retest.json -s scope.json -o delta.md --html
```

- Findings are matched by target + first CVE when one is listed, otherwise target + title (falling back to template id or finding id).
- The result classifies each baseline finding as resolved or persistent, and each current finding as new. Persistent findings carry a severity drift: escalated, downgraded or unchanged.
- `remediationRate` is resolved findings divided by baseline findings, as a percentage.
- `-s` is fail-closed: a scope file that cannot be loaded is an error, never a silent pass. Without `-s`, no scope filtering happens.
- `vapt diff` needs no LLM configuration — it is a local comparison.
- `--json` prints the raw diff object to stdout and returns; `-o` is **not** written in that mode.
- Without `--json`: the colored summary prints on stdout; with `-o` the Markdown (or `--html` HTML) is saved to the file; with `-q` and no `-o`, the Markdown body is printed to stdout instead.

## Tips for client-ready output

- Put the real engagement name in `scope.json` `engagement` — it becomes the HTML title.
- Run `vapt scan` before `vapt report` so section 2 reflects commands that actually ran, and keep the ledger in the same output directory.
- Use `--html` for the client deliverable and keep the Markdown as the diffable source.
- Review every `flaggedForManualReview` item before sending — see [Verification](../verification/).
- After remediation, re-test with the same skill and run `vapt diff`: the delta report is usually what the client signs off on.
