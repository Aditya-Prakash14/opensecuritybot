---
title: CLI Reference
description: Every `vapt` command with its options and defaults, plus environment variables and the output contract.
---

One page for every command, matching the actual CLI. `vapt` with no command starts the interactive session; its options configure the session workspace. Each subcommand has its own options after the command name.

## vapt — interactive session

```sh
vapt [-f <findings>] [-s <scope>] [-c <cache>] [-o <out>]
```

| Option | Default | Description |
| --- | --- | --- |
| `-f, --findings <path>` | `./findings.json` | findings JSON for the session |
| `-s, --scope <path>` | `./scope.json` | confirmed scope file |
| `-c, --cache <dir>` | `./cve-cache` | NVD cve-cache directory |
| `-o, --out <dir>` | `./report` | report output directory |

Starts a Claude-Code-style REPL with a welcome card, streamed answers and boxed triage cards. It needs a TTY; without one the command errors and points at `vapt triage`. A missing or invalid scope or findings file produces a note in the welcome card instead of failing, but `/triage` and `/report` refuse to run without a scope.

| Slash command | Action |
| --- | --- |
| `/triage [id]` | triage the whole queue, or one finding by id |
| `/findings` | in-scope queue, severity-descending, triaged/queued state |
| `/scope` | the confirmed engagement targets |
| `/report` | compile and save the full report |
| `/save [path]` | persist triaged results and history (default `<out>/session-state.json`) |
| `/load [path]` | restore a saved session state |
| `/clear` | clear the screen |
| `/help` | command list |
| `/exit` | leave (`/quit` and `/q` also exit) |

Aliases: `/t`, `/f`, `/r`, `/s`, `/?`. Tab completes slash commands and finding ids. Anything that is not a slash command is a question answered by the agent, grounded in the loaded scope, findings and triage results.

```sh
cd acme
vapt                      # uses ./scope.json, ./findings.json, ./cve-cache, ./report
```

## vapt setup

```sh
vapt setup
```

Provider → API key (masked) → model. The model list is fetched from the provider's `/models` endpoint when reachable. Saves to `~/.config/vapt/config.json`, owner-only (0600); `VAPT_CONFIG_DIR` overrides the directory. Needs a TTY — for headless use set `VAPT_LLM_BASE_URL`, `VAPT_LLM_MODEL` and `VAPT_LLM_API_KEY` instead. The same wizard starts automatically when `vapt`, `triage` or `report` finds no configuration on a TTY.

```sh
vapt setup
```

## vapt init

```sh
vapt init [-d <dir>]
```

| Option | Default | Description |
| --- | --- | --- |
| `-d, --dir <dir>` | `.` | workspace directory |

Creates `<dir>/scope.json` (template with a placeholder engagement name and example targets), `<dir>/cve-cache/` and `<dir>/report/`. Refuses to overwrite an existing `scope.json`.

```sh
vapt init -d engagements/acme
```

## vapt triage

```sh
vapt triage -f <findings> [-s <scope>] [-c <cache>] [-o <dir>] [--id <id>] [--json] [-q]
```

| Option | Default | Description |
| --- | --- | --- |
| `-f, --findings <path>` | required | normalized findings; comma-separated paths accepted |
| `-s, --scope <path>` | `./scope.json` | confirmed scope file |
| `-c, --cache <dir>` | `./cve-cache` | NVD cve-cache directory |
| `--id <findingId>` | — | triage only this finding (must be in scope) |
| `--json` | off | emit a structured JSON array instead of markdown; up to 4 calls in flight |
| `-q, --quiet` | off | suppress progress messages on stderr |

Markdown mode streams one triage per finding, severity-descending. `--json` runs concurrently but the array keeps severity order; failed findings are omitted from the array, reported on stderr, and set exit code `1`.

```sh
vapt triage -f findings.json -s scope.json
vapt triage -f findings.json --json | jq '.[] | select(.triage.adjustedSeverity == "high")'
vapt triage -f findings.json --id F-2
```

## vapt report

```sh
vapt report -f <findings> [-s <scope>] [-c <cache>] [-o <dir>] [--html] [--json] [-q]
```

| Option | Default | Description |
| --- | --- | --- |
| `-f, --findings <path>` | required | normalized findings; comma-separated paths accepted |
| `-s, --scope <path>` | `./scope.json` | confirmed scope file |
| `-c, --cache <dir>` | `./cve-cache` | NVD cve-cache directory |
| `-o, --out <dir>` | `./report` | report output directory |
| `--html` | off | also save a standalone HTML report |
| `--json` | off | emit the JSON payload (`scope`, `findingsCount`, `markdown`, `failures`) instead of markdown |
| `-q, --quiet` | off | suppress progress messages on stderr |

Triages every finding (up to 4 in flight), then one synthesis call writes sections 1–5. The Markdown is printed to stdout before saving; files are still saved when `--json` is used. Exit code is `1` if any finding failed triage or if saving failed.

```sh
vapt report -f findings.json -s scope.json -c cve-cache -o report/
vapt report -f findings.json -s scope.json --html
```

## vapt diff

```sh
vapt diff -b <baseline> -c <current> [-s <scope>] [-o <file>] [--html] [--json] [-q]
```

| Option | Default | Description |
| --- | --- | --- |
| `-b, --baseline <path>` | required | baseline findings file (JSON, JSONL or ZAP JSON) |
| `-c, --current <path>` | required | current findings file after remediation (JSON, JSONL or ZAP JSON) |
| `-s, --scope <path>` | — | confirmed scope file; filters out-of-scope findings, fail-closed |
| `-o, --out <path>` | — | save the delta report to a file (Markdown or HTML) |
| `--html` | off | format the report as standalone HTML |
| `--json` | off | emit the structured diff JSON to stdout |
| `-q, --quiet` | off | suppress the console summary |

Note the flag collision: for `diff`, `-c` is `--current`; everywhere else `-c` is `--cache`. `diff` needs no LLM configuration.

Without `--json`, the colored summary prints on stdout; with `-o` the Markdown (or HTML with `--html`) is saved to the file; with `-q` and no `-o`, the Markdown body goes to stdout instead. With `--json`, the JSON object is emitted and `-o` is not written.

```sh
vapt diff -b baseline.json -c retest.json -s scope.json -o delta.md
vapt diff -b baseline.json -c retest.json --html -o delta.html
```

## vapt skills

```sh
vapt skills [--dir <dir>]
```

| Option | Default | Description |
| --- | --- | --- |
| `--dir <dir>` | `VAPT_SKILLS_DIR`, else the `skills/` bundled with the installed package | skills directory |

Lists each skill's name, risk, target kinds, tools and description. Every `*.json` file in the directory is loaded and validated; one malformed file fails the command.

```sh
vapt skills
```

## vapt scan

```sh
vapt scan --skill <name> --target <target> [-s <scope>] [-o <dir>] [--ledger <path>] [--dry-run] [-y] [-q]
```

| Option | Default | Description |
| --- | --- | --- |
| `--skill <name>` | required | skill to run (see `vapt skills`) |
| `--target <target>` | required | one authorized target; in scope and matching the skill's `appliesTo` |
| `-s, --scope <path>` | `./scope.json` | confirmed scope file |
| `-o, --out <dir>` | `./findings` | findings output directory |
| `--ledger <path>` | `./report/scan-ledger.jsonl` | append-only execution ledger |
| `--dry-run` | off | print the exact commands, execute nothing, write nothing |
| `-y, --yes` | off | skip per-step confirmation; required without a TTY |
| `-q, --quiet` | off | suppress progress messages on stderr |

Runs reviewed, allowlisted argv with `shell: false`, re-checks scope before every step, and writes normalized findings. Exit code is `1` if any step failed; a run that produced no findings is not an error by itself. See [Scan Skills](../scan-skills/) for the safety model and the ledger format.

```sh
vapt scan --skill http-baseline --target https://app.acme.com --dry-run
vapt scan --skill service-discovery --target 10.10.0.5 --yes -o findings/
```

## vapt workspace

```sh
vapt workspace list
vapt workspace create <name> [-e <title>]
vapt workspace use <name>
vapt workspace current
```

| Command | Action |
| --- | --- |
| `list` | list all workspaces, marking the active one |
| `create <name> [-e, --engagement <title>]` | create a workspace with `scope.json`, `cve-cache/`, `report/` |
| `use <name>` | switch the active workspace (alias: `switch`) |
| `current` | print the active workspace |

Workspaces live under `~/.config/vapt/workspaces/` (`VAPT_WORKSPACES_ROOT` overrides the root). Names allow letters, digits, dot, underscore and dash. The active workspace is recorded in the config file — `use` therefore requires `vapt setup` to have run. `create` also activates the new workspace when none was active yet. Relative paths that do not exist in the current directory are resolved inside the active workspace.

```sh
vapt workspace create acme -e "Acme Q4 external"
vapt workspace use acme
vapt workspace current
```

## Environment variables

Environment variables take precedence over the config file. A `.env` in the current working directory is loaded only when `VAPT_LOAD_DOTENV=1` is exported.

| Variable | Default | Description |
| --- | --- | --- |
| `VAPT_LLM_BASE_URL` | `https://api.openai.com/v1` | any OpenAI-compatible endpoint |
| `VAPT_LLM_MODEL` | — | required unless the config file sets a model |
| `VAPT_LLM_API_KEY` | — | sent as `Bearer`; for Anthropic native requests as `x-api-key` |
| `VAPT_LLM_PROVIDER` | — | only `anthropic` has special meaning (native messages API detection) |
| `VAPT_LLM_TIMEOUT_MS` | `120000` non-streaming, `300000` streaming | when set, applies to both paths |
| `VAPT_LLM_TEMPERATURE` | not sent | included only when set and numeric |
| `VAPT_LLM_MAX_TOKENS` | `16000` | Anthropic native requests only; lower it for older Claude models that cap output at 4096 |
| `VAPT_LLM_RETRY_DELAY_MS` | `2000` | fallback retry wait when the response gives no retry hint; capped at 60000 |
| `VAPT_CONFIG_DIR` | `~/.config/vapt` | config directory, and parent of the workspaces root |
| `VAPT_NVD_API_KEY` | — | sent to the NVD API; shortens prefetch waits |
| `VAPT_NVD_MAX` | `25` | maximum CVEs prefetched per run; `0` disables |
| `VAPT_NVD_DELAY_MS` | `6000`, or `700` with `VAPT_NVD_API_KEY` | wait between NVD requests |
| `VAPT_SKILLS_DIR` | bundled `skills/` | replaces the scan-skills directory |
| `VAPT_WORKSPACES_ROOT` | `<VAPT_CONFIG_DIR>/workspaces` | workspace root |
| `VAPT_REPORT_MAX_PROMPT_TOKENS` | `120000` | synthesis prompt size warning; `0` disables the check |

## Output contract

- **stdout** carries data: Markdown reports, triage JSON, listings, diff JSON, HTML when `--html` is the only output. `--json` is pipe-safe.
- **stderr** carries chrome: progress, spinners, skips, warnings, `saved:` confirmations and errors.
- Exit code `1` when: a triage fails (`triage`, `report`), a scan step fails, a report save fails, or any unhandled error occurs. Partial results are still emitted in the failure cases.
- Exit code `0` in the normal case, including runs that legitimately produced no findings.
- `vapt diff` prints its summary on stdout; `-q` without `-o` prints the Markdown body to stdout instead, and `--json` returns the diff object without writing `-o`.
- `vapt --version` prints the version; `vapt --help` shows usage and examples.
