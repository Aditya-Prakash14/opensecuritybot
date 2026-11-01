---
title: Code Audit
description: Audit local source with reviewed attack-class knowledge and feed the candidates into the same triage and report pipeline.
---

`vapt audit <path>` reviews local source code and writes candidate findings — no scanner, no target traffic. It is the third finding source in the pipeline, alongside scanner output and [scan skills](../scan-skills/), and it produces the same normalized shape, so `vapt triage`, `vapt report`, `vapt diff` and the CVE verification are unchanged.

```sh
vapt audit ./src              # audit a directory
vapt audit . -o findings/     # whole repo, findings written to findings/
```

## Why it is a separate stage

The scanner path answers "what does the deployed target expose?". A code audit answers "what does this source do wrong on the way to that exposure?" — a missing authorization check, an ID parameter concatenated into a query, a secret in a log line. Those are visible in source long before a scanner can see them, and they are the vulnerabilities a scanner most often misses.

Candidates are exactly that: candidates. `vapt audit` cannot execute the code, so nothing it reports is confirmed. The tool's triage stage is the adversarial verifier, and `verify.ts` cross-checks every cited CVE afterwards — see [Verification](../verification/).

## The knowledge it applies

The attack classes and validation rules are reviewed, versioned content in `skills/audit/*.md`: the [Cloudflare security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT), which is the single-repo starting point of the vulnerability harness described in [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness). Each audit call receives the selected packs plus the source, and every call gets `audit-mode` and `validation-rules` — the candidate gate that keeps "deviation from a checklist" out of the findings.

| Pack | Covers |
| --- | --- |
| `attack-classes` | core classes: injection, access control, file/resource handling, crypto and secrets, business logic, chains, wildcards, obvious things |
| `web-protocol-and-auth` | HTTP framing and cache, browser sessions, OAuth/OIDC/SAML, MFA and passkeys, API keys and mTLS |
| `client-side` | DOM and object state, cross-origin messaging, service workers and storage, information leaks, UI redress |
| `ai-and-llm` | prompt injection, retrieval and memory poisoning, tool and action binding, MCP trust, output handling |
| `cloud-and-deployment` | IAM, infrastructure as code, containers, serverless, ingress, runtime configuration |
| `supply-chain-and-release` | dependency resolution, generated inputs, CI, release and signing, updates, plugins |
| `protocols-rpc-and-messaging` | gRPC, GraphQL transports, Protobuf/Thrift, queues, brokers, webhooks, streaming |
| `resource-exhaustion-and-availability` | shared CPU, memory, disk, connections, workers, quotas, operator spend |
| `data-isolation-and-lifecycle` | tenant isolation, caches and search, export/backup, migration, retention, deletion, restore |
| `desktop-mobile-and-local-ipc` | native apps, deep links, webview bridges, exported components, helpers, daemons, local IPC |
| `memory-safety-and-binary` | memory safety, integers and ABI, concurrency, binary loaders, privileged interfaces |
| `audit-mode` | how this stage differs from triage, and what it must never claim |
| `validation-rules` | the candidate gate, vendored verbatim |

`audit-mode`, `validation-rules` and `attack-classes` are always included. Up to three companion packs are added automatically when the source matches their vocabulary (`express`/`jwt` source pulls in `web-protocol-and-auth`, `openai`/`mcp` pulls in `ai-and-llm`, and so on). `--knowledge <name,...>` replaces that selection, and `--knowledge all` applies every pack.

## Scope

An audit does not touch a network target, so it needs no scope file to run. Its findings are a different story: **before triage or report will process them, the audited path must appear in `scope.json` as a path target.** That check is the same `isInScope()` used for hosts, and it fails closed — an empty `inScope` list means the run stops rather than sending unverified findings to the model.

```json
{ "engagement": "Acme internal review", "targets": ["/Users/you/work/acme", "acme.com"] }
```

Path targets are matched as paths, never as hosts: the exact directory, or anything below it. A relative entry (`./src`, `myrepo/src`) matches the same tail of the audited absolute path. `vapt audit` prints the exact string to add when the target is not yet in scope.

## What is recorded

The findings file carries a coverage block next to the findings, so an audit is auditable:

```json
{
  "audit": {
    "root": "/Users/you/work/acme",
    "target": "/Users/you/work/acme",
    "filesScanned": 128,
    "filesSkipped": ["node_modules/: skipped directory", "logo.png: asset/binary extension"],
    "filesSkippedTotal": 431,
    "knowledgePacks": ["audit-mode", "validation-rules", "attack-classes", "web-protocol-and-auth"],
    "calls": 4,
    "malformedCandidates": 0
  },
  "findings": [
    {
      "id": "AUD-1",
      "target": "/Users/you/work/acme",
      "title": "SQL injection in GET /users/:id",
      "severity": "critical",
      "tool": "code-audit",
      "raw": { "file": "src/users.ts", "line": 6, "attackClass": "Injection", "evidence": "SELECT * FROM users WHERE id = ${req.params.id}", "trace": ["GET /users/:id", "db.query"], "fix": "Use a parameterized query." }
    }
  ]
}
```

One line per audit is appended to the same execution ledger `vapt scan` writes (`report/scan-ledger.jsonl`), and `vapt report` folds it into the report's Scope & Methodology section.

## Limits

- **Nothing is executed.** No build, no test, no fixture, no fuzz, no target traffic. Anything that needs a running system stays a candidate with its blocker named.
- **Read-only and bounded.** Symlinks are not followed; `node_modules`, `dist`, `build`, `vendor`, `target`, caches and report directories are skipped along with binaries and files over 200 KB. Over `--max-bytes` the run refuses to start rather than silently auditing half the tree.
- **Source goes to your LLM.** The configured endpoint receives every file in the audit. Point at a local model (Ollama) when the source is sensitive, as with any other stage.
- **Cost is one call per chunk** (`--chunk-bytes`, default 120 000 characters), sequential, plus the N+1 triage calls that follow if you run `triage` or `report`.
- **No coverage critics.** The upstream harness runs isolated hunters, coverage critics and per-target sandboxes across many agents. `vapt audit` is a single agent: it is one pass with the reviewed classes, and repeated passes over a changed tree are how coverage improves.
- **Prompt-injection surface.** Audited source is untrusted input to the model. Files are wrapped in escaped data tags, and both the system prompt and the audit instruction say source is data, never instructions — the same rule that already applies to scanner output.
