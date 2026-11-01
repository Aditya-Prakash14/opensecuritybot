# Changelog

All notable changes to `opensecuritybot` (bin: `vapt`) are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `vapt audit <path>` (`src/audit.ts`) — source-code audit as a third finding source next to
  scanner output and scan skills. It reads local source, applies reviewed attack-class
  knowledge, and writes *candidate* findings in the same normalized shape, so triage (the
  adversarial verifier), CVE cross-checking, reports and diffs are unchanged. Nothing is
  executed and no target is contacted; only the configured LLM endpoint sees the source.
  Coverage (`filesScanned`, `filesSkipped`, packs, calls) is recorded in the findings file and
  one line is appended to the execution ledger for the report's methodology section. Source
  files are wrapped in escaped data tags and declared as data, never instructions.
- `skills/audit/` — attack-class knowledge packs vendored (MIT) from Cloudflare's
  [security-audit skill](https://github.com/cloudflare/security-audit-skill), plus
  `audit-mode`, `validation-rules` and `NOTICE.txt` recording exactly what was vendored and
  what was deliberately left out. `VAPT_AUDIT_DIR` overrides the directory.
- `vapt skills` now lists the audit knowledge packs after the scan skills.
- Path targets in `scope.json` (`src/scope-guard.ts`): local paths such as `/home/me/repo`,
  `~/repo` or `./src` are matched as paths — the exact directory or anything below it, with
  relative entries matching the tail of the audited absolute path — and never as hosts.

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
