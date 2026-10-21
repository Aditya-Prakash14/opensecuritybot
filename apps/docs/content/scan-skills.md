---
title: Scan Skills
description: Review, run and write the allowlisted scan-skill playbooks that `vapt scan` executes inside a confirmed scope.
---

A **skill** is a reviewed, declarative JSON playbook for a scanner command — not LLM-generated argv. The model reasons about findings; it never writes the command that runs. `vapt skills` lists what is available, `vapt scan` runs one against a single in-scope target and writes normalized findings.

## What a skill is

A JSON file in the skills directory with this shape (this is the built-in `http-baseline`):

```json
{
  "name": "http-baseline",
  "description": "Passive HTTP fingerprint and low-noise misconfiguration/exposure templates.",
  "appliesTo": ["url", "host"],
  "risk": "passive",
  "steps": [
    { "tool": "httpx", "args": ["-json", "-silent", "-u", "{{target}}"] },
    { "tool": "nuclei", "args": ["-jsonl", "-silent", "-severity", "low,medium,high,critical", "-tags", "exposure,misconfig", "-u", "{{target}}"] }
  ],
  "parsers": ["httpx-jsonl", "nuclei-jsonl"]
}
```

None of the argv comes from the model at runtime. The only substitution is `{{target}}`, replaced with the target you pass on the command line.

## Safety model

- Tool allowlist: only `nmap`, `nuclei`, `httpx`, `masscan`, `subfinder`, `wpscan` and `ffuf` are valid step tools. Anything else is rejected at load time. Every allowlisted tool reports findings; none exploit.
- No shells: each step is an argv array executed with `shell: false`. There is no command string to inject into.
- One placeholder: `{{target}}` is the only allowed placeholder; any other `{{...}}` fails validation.
- Scope re-checked per step: immediately before each step runs, the target is matched with the same scope matcher used everywhere else. An out-of-scope target throws and nothing executes.
- Metadata endpoints refused: `169.254.169.254`, `fd00:ec2::254` and `metadata.google.internal` are always refused, even if someone lists them in `scope.json`.
- Per-step confirmation: every step prints its exact argv and asks `y/N` before running. `--yes` skips the prompt and is required in non-interactive runs.
- Timeout and output cap: each step has a timeout (per-step `timeoutMs`, default `120000` ms) and captures at most 10 MB across stdout and stderr; excess output is dropped.

The allowlist constrains the tool *name*. `spawn` still resolves it from `PATH`, so the binary that actually runs is whatever `nmap`, `nuclei`, `httpx`, `masscan`, `subfinder`, `wpscan` or `ffuf` resolves to on your machine.

## Listing skills

```sh
vapt skills
vapt skills --dir ~/engagements/acme/skills
```

The default directory is `VAPT_SKILLS_DIR` when set, otherwise the `skills/` directory bundled inside the installed package (so a global install works from any directory). `VAPT_SKILLS_DIR` **replaces** that directory; it does not add to it. Every `*.json` file in the directory is loaded and validated, so one malformed file fails the listing with the file name and the validation error.

## Running a scan

```sh
vapt scan --skill http-baseline --target https://app.acme.com --dry-run
vapt scan --skill http-baseline --target https://app.acme.com
vapt scan --skill service-discovery --target 10.10.0.5 --yes -o findings/
```

| Option | Default | Description |
| --- | --- | --- |
| `--skill <name>` | required | skill to run (see `vapt skills`) |
| `--target <target>` | required | one authorized target; must be in scope and match the skill's `appliesTo` |
| `-s, --scope <path>` | `./scope.json` | confirmed scope file |
| `-o, --out <dir>` | `./findings` | findings output directory |
| `--ledger <path>` | `./report/scan-ledger.jsonl` | append-only execution ledger |
| `--dry-run` | off | print the exact commands, execute nothing, write nothing |
| `-y, --yes` | off | skip per-step confirmation; required when stdin is not a TTY |
| `-q, --quiet` | off | suppress progress messages on stderr |

Target kind is detected from the string: a value with a `scheme://` is `url`, a dotted IPv4 address or anything containing `:` is `ip`, everything else is `host`. The skill must list that kind in `appliesTo` or the run is rejected.

`--dry-run` still checks that the skill applies and that the target is in scope; it just never executes or writes. Confirmation accepts `y` or `yes`; anything else aborts the run with exit code `1`.

## Built-in skills

| Name | Risk | Applies to | Steps | Parsers |
| --- | --- | --- | --- | --- |
| `http-baseline` | passive | `url`, `host` | 1. `httpx -json -silent -u {{target}}` 2. `nuclei -jsonl -silent -severity low,medium,high,critical -tags exposure,misconfig -u {{target}}` | `httpx-jsonl`, `nuclei-jsonl` |
| `web-fingerprint` | passive | `url`, `host` | 1. `httpx -json -silent -tech-detect -title -status-code -web-server -u {{target}}` 2. `nuclei -jsonl -silent -tags tech -u {{target}}` | `httpx-jsonl`, `nuclei-jsonl` |
| `cve-scan` | active | `url`, `host` | `nuclei -jsonl -silent -tags cve -severity medium,high,critical -u {{target}}` | `nuclei-jsonl` |
| `exposed-panels` | passive | `url`, `host` | `nuclei -jsonl -silent -tags panel,login -u {{target}}` | `nuclei-jsonl` |
| `takeover-check` | passive | `url`, `host` | `nuclei -jsonl -silent -tags takeover -u {{target}}` | `nuclei-jsonl` |
| `service-discovery` | active | `host`, `ip` | `nmap -sV --top-ports 1000 -T3 -oG - {{target}}` | `nmap-grepable` |
| `port-sweep` | active | `host`, `ip` | `masscan -p <common TCP ports> --rate 1000 -oJ - {{target}}` | `masscan-json` |
| `subdomain-discovery` | passive | `host` | `subfinder -oJ -silent -duc -d {{target}}` | `subfinder-jsonl` |
| `content-discovery` | active | `url` | `ffuf -json -s -maxtime 300 -mc … -w <wordlist> -u {{target}}/FUZZ` | `ffuf-json` |
| `wpscan` | active | `url`, `host` | `wpscan --url {{target}} --enumerate vp,vt,u --format json --no-banner` | `wpscan-json` |

`wpscan`'s vulnerability (CVE) data needs a WPScan API token. Because skill argv is written to the ledger, the token is read from the `WPSCAN_API_TOKEN` environment variable of the process running `vapt scan`, never from argv. Without a token, wpscan still enumerates version, plugins, themes and users but returns no CVE data. `content-discovery`'s wordlist path is environment-specific (default assumes a Kali-style path) — adjust it for your box; a missing wordlist makes ffuf exit with zero findings, not a crash.

When to use each: `web-fingerprint` maps what a host runs (tech, title, server) before deeper work; `cve-scan` is the active known-CVE pass once a scope is confirmed (it runs for many minutes — note the long `timeoutMs`); `exposed-panels` surfaces admin/login interfaces that should not be public; `takeover-check` catches dangling DNS records pointing at unclaimed services.

`risk` is a review label, not a runtime control: `passive` means fingerprinting and low-noise templates; `active` means service probes (top 1000 TCP ports with version detection). Pick the label honestly when you add a skill.

## Output

Scanner output is normalized into the same findings format the rest of the pipeline consumes, so deduplication, scope filtering, triage and reporting work unchanged:

- httpx JSONL → one `info` record per URL (status, title, tech, webserver).
- nuclei JSONL → one record per matched template (template id, target, title, severity, description).
- nmap grepable → one `info` record per open port (`host:port`, service, version).

The run writes `<out>/<skill-name>-<timestamp>.json` and prints `saved: <path>` plus a suggested `vapt report` command. If no records were produced, nothing is written and the CLI prints `no findings produced` — that is not an error by itself.

## The execution ledger

Every executed step appends one JSON line to the ledger (default `report/scan-ledger.jsonl`):

| Field | Meaning |
| --- | --- |
| `ts` | ISO timestamp |
| `skill` | skill name |
| `target` | target as passed |
| `step` | 1-based step number |
| `tool` | tool name |
| `argv` | full argv after `{{target}}` substitution |
| `exitCode` | process exit code; `null` when the tool could not be spawned |
| `durationMs` | wall time |
| `outputSha256` | SHA-256 of captured stdout |
| `outputBytes` | captured stdout size |

Why: the report's Scope & Methodology section has to show what was actually run, not what was intended. `vapt report` reads `<out>/scan-ledger.jsonl` (relative to its own output directory) and folds the steps into the synthesis prompt for section 2. Ledger writes are append-only, and a write failure is an error — a missing audit record should be visible. Dry runs and aborted confirmations write nothing.

## Adding your own skill

A skill is a code change, not configuration: drop a JSON file into the skills directory, re-run `vapt skills` to load it, and have a reviewer read the argv line by line. A skill that cannot be reviewed should not be run.

```json
{
  "name": "web-ports",
  "description": "Version detection on common web ports.",
  "appliesTo": ["host", "ip"],
  "risk": "active",
  "steps": [
    { "tool": "nmap", "args": ["-sV", "-p", "80,443,8080,8443", "-T3", "-oG", "-", "{{target}}"], "timeoutMs": 120000 }
  ],
  "parsers": ["nmap-grepable"]
}
```

Validation rules applied at load time:

- The file parses as a JSON object (not an array).
- `name` and `description` are non-empty strings.
- `appliesTo` is a non-empty array of `url`, `host`, `ip`.
- `risk` is `passive` or `active`.
- `steps` is a non-empty array; each step has a `tool` from the allowlist, an array of string `args` containing only `{{target}}` as a placeholder, and an optional positive `timeoutMs`.
- `parsers` is a non-empty array of `httpx-jsonl`, `nuclei-jsonl`, `nmap-grepable`. The count must equal the number of steps: parser *i* normalizes step *i*.

## Honest limits

- The ledger is append-only with no rotation. It grows with every step; rotate or archive it yourself between engagements.
- On timeout the runner sends `SIGKILL` to the direct child only. A grandchild holding the pipe can delay completion (see the `shortcut:` note in `src/runner.ts`).
- The 10 MB capture cap is shared across stdout and stderr; anything beyond is silently dropped before parsing.
- `--yes` removes the per-step human check. In automation, the scope re-check is the only runtime gate — which is why the argv you pre-reviewed matters.
- Findings quality is still scanner quality. A skill normalizes output; it does not improve detection or verify results.
- `vapt report` reads the ledger from its own output directory. If you point `scan --ledger` somewhere else, pass a matching `report -o`.
