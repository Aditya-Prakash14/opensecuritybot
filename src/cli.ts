#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Command } from "commander";
import { loadCveCache } from "./cve-cache.js";
import { buildReport } from "./report.js";
import { filterInScope, loadScope, scopeEntries } from "./scope-guard.js";
import { type TriageCtx, sortBySeverity, triageFindingJson, triageFindingMarkdown } from "./triage.js";
import type { CveEntry, Finding, Scope, TriageResult } from "./types.js";

const TARGET_KEYS = ["target", "host", "url", "endpoint", "matched_at", "matchedAt", "asset"];
const ID_KEYS = ["id", "findingId", "template_id", "_id", "alertRef"];
const MAX_RAW = 8000;

function pickString(raw: Record<string, unknown>, keys: string[]): string | undefined {
  return keys.map((k) => raw[k]).find((v): v is string => typeof v === "string" && v.trim().length > 0);
}

function normalizeFinding(raw: unknown, i: number): Finding | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const target = pickString(o, TARGET_KEYS);
  if (!target) return null;
  const id = pickString(o, ID_KEYS) ?? `F-${i + 1}`;
  const size = JSON.stringify(raw).length;
  return { ...o, id, target, raw: size > MAX_RAW ? `[evidence omitted: ${size} bytes]` : raw };
}

function loadFindings(path: string): { findings: Finding[]; skipped: string[] } {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`${path}: not readable as JSON (${(e as Error).message})`);
  }
  const arr = Array.isArray(data) ? data : (data as { findings?: unknown })?.findings;
  if (!Array.isArray(arr) || arr.length === 0) throw new Error(`${path}: expected a non-empty array or { "findings": [...] }`);
  const findings: Finding[] = [];
  const skipped: string[] = [];
  arr.forEach((raw, i) => {
    const f = normalizeFinding(raw, i);
    if (f) findings.push(f);
    else skipped.push(`entry #${i + 1}: no target/host/url field`);
  });
  return { findings, skipped };
}

interface Prepared {
  scope: Scope;
  findings: Finding[];
  cache: Map<string, CveEntry>;
}

/** Load + scope-filter. Anything outside scope.json is dropped here, before any LLM call. */
function prepare(findingPath: string, scopePath: string, cacheDir: string): Prepared {
  const scope = loadScope(scopePath);
  const { findings, skipped } = loadFindings(findingPath);
  const { inScope, outOfScope } = filterInScope(findings, scopeEntries(scope));
  for (const s of skipped) console.error(`skip: ${s}`);
  for (const f of outOfScope) console.error(`skip: out of scope — ${f.id} (${f.target})`);
  if (inScope.length === 0) throw new Error("no in-scope findings to process");
  return { scope, findings: sortBySeverity(inScope), cache: loadCveCache(cacheDir) };
}

const program = new Command();
program.name("vapt").description("VAPT-Agent — triage, explain and report scanner findings (authorized engagements only)");

program
  .command("triage")
  .description("triage findings — human-readable markdown, or --json for the structured schema")
  .requiredOption("-f, --findings <path>", 'normalized findings JSON (array or { "findings": [...] })')
  .option("-s, --scope <path>", "confirmed scope file", "./scope.json")
  .option("-c, --cache <dir>", "NVD cve-cache directory", "./cve-cache")
  .option("--id <findingId>", "triage only one finding by id")
  .option("--json", "emit structured JSON instead of markdown")
  .action(async (opts: { findings: string; scope: string; cache: string; id?: string; json?: boolean }) => {
    const { scope, findings, cache } = prepare(opts.findings, opts.scope, opts.cache);
    const queue = opts.id ? findings.filter((f) => f.id === opts.id) : findings;
    if (queue.length === 0) throw new Error(`finding ${opts.id} not found among in-scope findings`);
    console.error(
      `plan: ${queue.length} finding(s), severity-desc: ${queue.map((f) => `${f.id}(${f.severity ?? "?"})`).join(", ")}`,
    );
    const ctx: TriageCtx = { scope, cache };
    const results: TriageResult[] = [];
    let failed = 0;
    for (const f of queue) {
      try {
        if (opts.json) {
          results.push(await triageFindingJson(f, ctx));
        } else {
          const md = await triageFindingMarkdown(f, ctx);
          process.stdout.write(`## ${f.id} — ${f.title ?? f.target} [${f.severity ?? "unknown"}]\n\n${md.trim()}\n\n---\n\n`);
        }
      } catch (e) {
        failed++;
        console.error(`fail: ${f.id}: ${(e as Error).message}`);
      }
    }
    if (opts.json) process.stdout.write(JSON.stringify(results, null, 2) + "\n");
    if (failed > 0) {
      console.error(`${failed}/${queue.length} finding(s) failed`);
      process.exitCode = 1;
    }
  });

program
  .command("report")
  .description("compile the full VAPT report (exec summary through roadmap) and save it under --out")
  .requiredOption("-f, --findings <path>", 'normalized findings JSON (array or { "findings": [...] })')
  .option("-s, --scope <path>", "confirmed scope file", "./scope.json")
  .option("-c, --cache <dir>", "NVD cve-cache directory", "./cve-cache")
  .option("-o, --out <dir>", "report output directory", "./report")
  .action(async (opts: { findings: string; scope: string; cache: string; out: string }) => {
    const { scope, findings, cache } = prepare(opts.findings, opts.scope, opts.cache);
    console.error(`plan: report over ${findings.length} in-scope finding(s) — per-finding triage, then synthesis`);
    const outcome = await buildReport(findings, { scope, cache }, (msg) => console.error(msg));
    mkdirSync(opts.out, { recursive: true });
    const file = join(opts.out, `vapt-report-${new Date().toISOString().slice(0, 19).replace(/[:-]/g, "")}.md`);
    writeFileSync(file, outcome.markdown + "\n");
    console.error(`saved: ${file}`);
    process.stdout.write(outcome.markdown + "\n");
    if (outcome.failures.length > 0) {
      console.error(`${outcome.failures.length}/${findings.length} finding(s) failed triage: ${outcome.failures.join("; ")}`);
      process.exitCode = 1;
    }
  });

program.parseAsync().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});