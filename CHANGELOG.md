# Changelog

All notable changes to `opensecuritybot` (bin: `vapt`) are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- **Scope:** a bare host now authorizes only itself. `acme.com` no longer matches
  `app.acme.com`; add `*.acme.com` to keep subdomains in scope. Affected findings are
  dropped as out of scope (fail closed), never processed by mistake.
- **`.env`:** loaded only when `VAPT_LOAD_DOTENV=1` is exported. A `.env` in an untrusted
  directory could redirect where findings are sent.

### Added

- Secret redaction before any data reaches the LLM (`redactSecrets` in `src/agent-prompt.ts`).
- `scope.json` `exclude` list (exclusions win everywhere) and `notBefore`/`notAfter` testing
  window, enforced by `vapt scan`.
- `vapt scan` resolves the target before each step and refuses link-local/metadata
  addresses; all link-local literals are refused too.
- Hash-chained scan ledger (`prevHash`) with `verifyLedger`; the report states the chain status.
- Report provenance footer (tool version, model, endpoint, system-prompt sha256, time) and
  `provenance` in `report --json`.
- `<out>/triage-cache.json`: triage results reused across report runs; analyst edits override
  the model until the finding, model or prompt changes.
- CISA KEV enrichment: known-exploited CVEs are marked `kev: true` (`VAPT_KEV=0` stays offline).
- `npm run eval` with a seed labeled set in `examples/eval/`.
- Anthropic prompt caching on the system prompt.
- Four reviewed scan skills: `web-fingerprint` and `takeover-check` and `exposed-panels`
  (passive) and `cve-scan` (active); nuclei steps carry explicit `timeoutMs` for broad tag sets.

### Changed

- Anthropic `max_tokens` default raised from 4096 to 16000; a reply cut off at the output
  limit now ends with a visible `[truncated: …]` marker on every provider.
- An `owaspCategory` that is not an OWASP Top 10 (2021) id flags the result for manual review.
- Terminal shows a red `KEV` marker on findings citing a CISA Known Exploited CVE (`/findings`,
  `vapt triage` header) and a `kev` count on the session card.
- Triage cards show the `[verify]` cross-check note as its own `verify` row instead of inside the reasoning.
- `/report` prints the provenance line (model, endpoint, prompt sha256) and warns when the ledger hash chain is broken.
- `/findings` header adds `· N flagged` when any triaged result needs manual review.

### Security

- Terminal control characters are stripped from scanner data on load and from all LLM output.
- `/load` keeps only valid triage results and user/assistant history turns.

### Fixed

- `vapt diff` writes the Markdown report to stdout whenever it is not saved with `--out`;
  previously it did so only with `-q`. The console summary now goes to stderr so stdout stays data-only.
- `vapt diff` resolves `--baseline`, `--current` and `--scope` through the active workspace like `triage`/`report`/`scan`.
- LLM request timeout (`VAPT_LLM_TIMEOUT_MS`) now covers reading the response body, not just the headers.
- Scope matching and the metadata-address refusal share one host parser (`hostOf`); bracketed IPv6
  targets with a port (`[fd00::1]:8080`) now match scope entries correctly.
- Secret redaction no longer masks prose such as "Basic authentication" or "Bearer tokens"; a token
  must contain a digit.
- Known-exploited (KEV) CVEs are flagged even when no NVD record is cached (offline, `VAPT_NVD_MAX=0`).
- Streamed replies keep the final chunk's text when it arrives together with the output-limit signal.
- `scope.json` rejects `exclude` entries that carry a path, since exclusions match whole hosts and a
  path would silently exclude the entire host.
- `vapt triage --json` and the session's `/triage` share `report/triage-cache.json` with `vapt report`
  (`triage` gains `-o <dir>`), so `/report` after `/triage` makes no extra LLM calls.
- CVSS 4.0 base scores (`cvssMetricV40`) are read from NVD records when present.
- Removed unused code: `WorkspaceInfo.hasFindings`/`createdAt`, the `prefixMarker` stream option,
  the duplicate `PARSER_NAMES` list (skills validate against `NORMALIZERS`) and the duplicate
  `hostPattern` parser. `npm run eval` moved to `src/eval.ts` so it is type-checked by the build.

## [0.5.2] - 2026-10-17

### Fixed

- `vapt skills` and `vapt scan` resolve the bundled `skills/` directory relative to the
  installed package, not the current working directory. They previously failed on a global
  install unless run from a directory containing `skills/` (`VAPT_SKILLS_DIR` still overrides).

## [0.5.0] - 2026-10-17

First functional public release on npm. (An earlier accidental placeholder,
`0.0.0-stage`, is not a usable release.)

### Added

- Reviewed scan skills (`skills/`, `src/skills.ts`): declarative, allowlisted playbooks for `nmap`, `nuclei` and `httpx`.
- Scope-pinned runner (`src/runner.ts`): argv-only steps, `{{target}}` as the sole placeholder, scope re-checked before each step, per-step timeout and 10 MB output cap.
- Normalizers for httpx JSONL, nuclei JSONL and nmap grepable output (`src/normalizers.ts`).
- Append-only execution ledger (`report/scan-ledger.jsonl`) folded into the report's Scope & Methodology section.
- `vapt skills` to list available skills and `vapt scan` to run one and write normalized findings.

### Changed

- `vapt report` now includes the execution ledger in the methodology section.
- Scan output uses the existing findings format, so deduplication, scope filtering, triage and reporting work unchanged.

### Fixed

- Evidence longer than 8 KB is now actually replaced with a placeholder.
- Streaming requests now enforce their timeout after response headers arrive.
- HTML output filters link schemes before rendering.

### Security

- Session and diff fail closed when no valid scope is loaded.
- Prompt data tags are escaped, so scanner content cannot break out of its boundary.
- Workspace names are validated before use in paths.
- Scan runner refuses cloud metadata endpoints even when listed in scope.

[Unreleased]: https://github.com/Aditya-Prakash14/opensecuritybot/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/Aditya-Prakash14/opensecuritybot/compare/v0.5.0...v0.5.2
[0.5.0]: https://github.com/Aditya-Prakash14/opensecuritybot/releases/tag/v0.5.0
