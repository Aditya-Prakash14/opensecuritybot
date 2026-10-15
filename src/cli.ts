#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Command } from "commander";
import { loadCveCache } from "./cve-cache.js";
import { loadFindings } from "./findings.js";
import { buildReport, saveReport } from "./report.js";
import { filterInScope, ipv6RangeEntries, loadScope, scopeEntries } from "./scope-guard.js";
import { startSession } from "./session.js";
import { type TriageCtx, sortBySeverity, triageFindingJson, triageFindingMarkdownStream } from "./triage.js";
import { bold, dim, green, red, severityColor, spinner, streamMarkdown, yellow } from "./ui.js";
import type { CveEntry, Finding, Scope, TriageResult } from "./types.js";

interface Prepared {
  scope: Scope;
  findings: Finding[];
  cache: Map<string, CveEntry>;
}

/** Load + scope-filter. Anything outside scope.json is dropped here, before any LLM call. */
function prepare(findingPath: string, scopePath: string, cacheDir: string): Prepared {
  const scope = loadScope(scopePath);
  const entries = scopeEntries(scope);
  for (const e of ipv6RangeEntries(entries)) {
    console.error(yellow(`warn: IPv6 range not matchable — findings on it will be skipped as out of scope: ${e}`));
  }
  const { findings, skipped, duplicates } = loadFindings(findingPath);
  const { inScope, outOfScope } = filterInScope(findings, entries);
  for (const s of skipped) console.error(dim(`skip: ${s}`));
  for (const d of duplicates) console.error(yellow(`warn: duplicate finding id — ${d}`));
  for (const f of outOfScope) console.error(dim(`skip: out of scope — ${f.id} (${f.target})`));
  if (inScope.length === 0) throw new Error("no in-scope findings to process");
  return { scope, findings: sortBySeverity(inScope), cache: loadCveCache(cacheDir) };
}

const program = new Command();
program
  .name("vapt")
  .version("0.3.0")
  .description("VAPT-Agent — triage, explain and report scanner findings (authorized engagements only)")
  .option("-f, --findings <path>", "findings JSON for the interactive session", "./findings.json")
  .option("-s, --scope <path>", "confirmed scope file", "./scope.json")
  .option("-c, --cache <dir>", "NVD cve-cache directory", "./cve-cache")
  .option("-o, --out <dir>", "report output directory", "./report")
  .action(async (opts: { findings: string; scope: string; cache: string; out: string }) => {
    await startSession(opts);
  });

program
  .command("init")
  .description("scaffold an engagement workspace (scope.json, cve-cache/, report/)")
  .option("-d, --dir <dir>", "workspace directory", ".")
  .action((opts: { dir: string }) => {
    const dir = opts.dir;
    mkdirSync(dir, { recursive: true });
    const scopePath = join(dir, "scope.json");
    if (existsSync(scopePath)) throw new Error(`${scopePath} already exists — not overwriting`);
    writeFileSync(
      scopePath,
      JSON.stringify(
        { engagement: "REPLACE ME — engagement name", targets: ["example.com", "*.api.example.com", "10.10.0.0/24"] },
        null,
        2,
      ) + "\n",
    );
    mkdirSync(join(dir, "cve-cache"), { recursive: true });
    mkdirSync(join(dir, "report"), { recursive: true });
    console.error(`${green("created")} ${scopePath}`);
    console.error(`${green("created")} ${join(dir, "cve-cache")}/, ${join(dir, "report")}/`);
    console.error(dim(`next: edit ${scopePath} with the authorized targets, drop your scanner output at ${join(dir, "findings.json")}, then run \`vapt\``));
  });

program
  .command("triage")
  .description("triage findings — streamed markdown, or --json for the structured schema")
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
      dim(`plan: ${queue.length} finding(s), severity-desc: ${queue.map((f) => `${f.id}(${f.severity ?? "?"})`).join(", ")}`),
    );
    const ctx: TriageCtx = { scope, cache };
    const results: TriageResult[] = [];
    let failed = 0;
    for (const f of queue) {
      if (opts.json) {
        const sp = spinner(`Triaging ${f.id} (${f.severity ?? "?"})`);
        try {
          results.push(await triageFindingJson(f, ctx));
          sp.stop();
        } catch (e) {
          sp.stop();
          failed++;
          console.error(red(`fail: ${f.id}: ${(e as Error).message}`));
        }
      } else {
        process.stdout.write(`\n${bold(f.id)} — ${f.title ?? f.target} ${severityColor(f.severity)(`[${f.severity ?? "unknown"}]`)}\n\n`);
        const sp = spinner(`Triaging ${f.id}`);
        try {
          await streamMarkdown(triageFindingMarkdownStream(f, ctx), { onFirstChunk: () => sp.stop() });
        } catch (e) {
          failed++;
          console.error(red(`fail: ${f.id}: ${(e as Error).message}`));
        } finally {
          sp.stop();
        }
        process.stdout.write("\n");
      }
    }
    if (opts.json) process.stdout.write(JSON.stringify(results, null, 2) + "\n");
    if (failed > 0) {
      console.error(red(`${failed}/${queue.length} finding(s) failed`));
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
    mkdirSync(opts.out, { recursive: true }); // fail fast: a bad --out path must not cost N+1 LLM calls
    console.error(dim(`plan: report over ${findings.length} in-scope finding(s) — per-finding triage, then synthesis`));
    const outcome = await buildReport(findings, { scope, cache }, (msg) => console.error(dim(msg)));
    process.stdout.write(outcome.markdown + "\n"); // print before saving: a save failure must not discard the report
    let saveFailed = false;
    try {
      const file = saveReport(outcome.markdown, opts.out);
      console.error(green(`saved: ${file}`));
    } catch (e) {
      saveFailed = true;
      console.error(yellow(`warn: could not save report (${(e as Error).message}) — printed above only`));
    }
    if (outcome.failures.length > 0) {
      console.error(red(`${outcome.failures.length}/${findings.length} finding(s) failed triage: ${outcome.failures.join("; ")}`));
      process.exitCode = 1;
    }
    if (saveFailed) process.exitCode = 1;
  });

program.parseAsync().catch((e: unknown) => {
  console.error(red(e instanceof Error ? e.message : String(e)));
  process.exit(1);
});