#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Command } from "commander";
import { loadCveCache } from "./cve-cache.js";
import { loadFindings } from "./findings.js";
import { buildReport, renderReportHtml, saveReport, saveReportHtml } from "./report.js";
import { filterInScope, loadScope, scopeEntries } from "./scope-guard.js";
import { startSession } from "./session.js";
import { ensureConfigured, runSetup } from "./setup.js";
import { type TriageCtx, sortBySeverity, triageFindingJson, triageFindingMarkdownStream } from "./triage.js";
import { bold, dim, findingHeader, green, red, severityColor, spinner, streamMarkdown, yellow } from "./ui.js";
import { compareFindings, printDiffSummary, renderDiffHtml, renderDiffMarkdown } from "./diff.js";
import {
  createWorkspace,
  getActiveWorkspace,
  listWorkspaces,
  resolveWorkspacePath,
  setActiveWorkspace,
} from "./workspace.js";
import type { CveEntry, Finding, Scope, TriageResult } from "./types.js";

interface Prepared {
  scope: Scope;
  findings: Finding[];
  cache: Map<string, CveEntry>;
}

/** Load + scope-filter. Anything outside scope.json is dropped here, before any LLM call. */
function prepare(findingPath: string | string[], scopePath: string, cacheDir: string, quiet = false): Prepared {
  const resolvedScope = resolveWorkspacePath(scopePath);
  const resolvedCache = resolveWorkspacePath(cacheDir);
  const scope = loadScope(resolvedScope);
  const entries = scopeEntries(scope);

  const rawPaths = Array.isArray(findingPath)
    ? findingPath
    : findingPath.includes(",")
      ? findingPath.split(",").map((s) => s.trim()).filter(Boolean)
      : [findingPath];
  const paths = rawPaths.map((p) => resolveWorkspacePath(p));
  const { findings, skipped, duplicates } = loadFindings(paths);
  const { inScope, outOfScope } = filterInScope(findings, entries);
  if (!quiet) {
    for (const s of skipped) console.error(dim(`skip: ${s}`));
    for (const d of duplicates) console.error(yellow(`warn: duplicate finding id — ${d}`));
    for (const f of outOfScope) console.error(dim(`skip: out of scope — ${f.id} (${f.target})`));
  }
  if (inScope.length === 0) throw new Error("no in-scope findings to process");
  return { scope, findings: sortBySeverity(inScope), cache: loadCveCache(resolvedCache) };
}

const program = new Command();
program
  .name("vapt")
  .version("0.4.0")
  .enablePositionalOptions() // subcommand flags (triage -f …) must not be swallowed by the program-level options
  .description("VAPT-Agent — triage, explain and report scanner findings (authorized engagements only)")
  .option("-f, --findings <path>", "findings JSON for the interactive session", "./findings.json")
  .option("-s, --scope <path>", "confirmed scope file", "./scope.json")
  .option("-c, --cache <dir>", "NVD cve-cache directory", "./cve-cache")
  .option("-o, --out <dir>", "report output directory", "./report")
  .action(async (opts: { findings: string; scope: string; cache: string; out: string }) => {
    await startSession(opts);
  });

program
  .command("setup")
  .description("first-run setup: pick a provider, API key and model (saved to ~/.config/vapt/config.json)")
  .action(async () => {
    await runSetup();
    console.error(dim("run `vapt` to start the interactive session"));
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
  .option("-q, --quiet", "suppress progress messages on stderr")
  .action(async (opts: { findings: string; scope: string; cache: string; id?: string; json?: boolean; quiet?: boolean }) => {
    await ensureConfigured();
    const { scope, findings, cache } = prepare(opts.findings, opts.scope, opts.cache, opts.quiet);
    const queue = opts.id ? findings.filter((f) => f.id === opts.id) : findings;
    if (queue.length === 0) throw new Error(`finding ${opts.id} not found among in-scope findings`);
    if (!opts.quiet) {
      console.error(
        dim(`plan: ${queue.length} finding(s), severity-desc: ${queue.map((f) => `${f.id}(${f.severity ?? "?"})`).join(", ")}`),
      );
    }
    const ctx: TriageCtx = { scope, cache };
    const results: TriageResult[] = [];
    let failed = 0;
    for (const f of queue) {
      if (opts.json) {
        const sp = !opts.quiet ? spinner(`Triaging ${f.id} (${f.severity ?? "?"})`) : { stop: () => {} };
        try {
          results.push(await triageFindingJson(f, ctx));
          sp.stop();
        } catch (e) {
          sp.stop();
          failed++;
          console.error(red(`fail: ${f.id}: ${(e as Error).message}`));
        }
      } else {
        process.stdout.write(findingHeader(f));
        const sp = !opts.quiet ? spinner(`Triaging ${f.id}`) : { stop: () => {} };
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
  .requiredOption("-f, --findings <path>", 'normalized findings JSON (comma-separated or single file)')
  .option("-s, --scope <path>", "confirmed scope file", "./scope.json")
  .option("-c, --cache <dir>", "NVD cve-cache directory", "./cve-cache")
  .option("-o, --out <dir>", "report output directory", "./report")
  .option("--html", "save standalone HTML report in addition to markdown")
  .option("--json", "emit structured JSON payload to stdout instead of markdown")
  .option("-q, --quiet", "suppress progress messages on stderr")
  .action(async (opts: { findings: string; scope: string; cache: string; out: string; html?: boolean; json?: boolean; quiet?: boolean }) => {
    await ensureConfigured();
    const { scope, findings, cache } = prepare(opts.findings, opts.scope, opts.cache, opts.quiet);
    mkdirSync(opts.out, { recursive: true }); // fail fast: a bad --out path must not cost N+1 LLM calls
    if (!opts.quiet) console.error(dim(`plan: report over ${findings.length} in-scope finding(s) — per-finding triage, then synthesis`));
    const outcome = await buildReport(findings, { scope, cache }, opts.quiet ? undefined : (msg) => console.error(dim(msg)));
    if (opts.json) {
      process.stdout.write(JSON.stringify({ scope, findingsCount: findings.length, ...outcome }, null, 2) + "\n");
    } else {
      process.stdout.write(outcome.markdown + "\n"); // print before saving: a save failure must not discard the report
    }
    let saveFailed = false;
    try {
      const file = saveReport(outcome.markdown, opts.out);
      if (!opts.quiet) console.error(green(`saved: ${file}`));
      if (opts.html) {
        const title = scope.engagement ? `${scope.engagement} — VAPT Report` : "VAPT Assessment Report";
        const html = renderReportHtml(outcome.markdown, title);
        const htmlFile = saveReportHtml(html, opts.out);
        if (!opts.quiet) console.error(green(`saved: ${htmlFile}`));
      }
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

program
  .command("diff")
  .description("compare baseline and current scan findings (remediation delta verification)")
  .requiredOption("-b, --baseline <path>", "baseline findings file (JSON, JSONL, or ZAP JSON)")
  .requiredOption("-c, --current <path>", "current findings file after remediation (JSON, JSONL, or ZAP JSON)")
  .option("-s, --scope <path>", "confirmed scope file (filters out-of-scope findings)")
  .option("-o, --out <path>", "save remediation delta report to file (Markdown or HTML)")
  .option("--html", "format report as standalone HTML")
  .option("--json", "emit structured diff JSON to stdout")
  .option("-q, --quiet", "suppress progress messages and console summary")
  .action(async (opts: { baseline: string; current: string; scope?: string; out?: string; html?: boolean; json?: boolean; quiet?: boolean }) => {
    let baselineFindings = loadFindings(opts.baseline).findings;
    let currentFindings = loadFindings(opts.current).findings;

    if (opts.scope && existsSync(opts.scope)) {
      try {
        const scope = loadScope(opts.scope);
        const entries = scopeEntries(scope);
        baselineFindings = filterInScope(baselineFindings, entries).inScope;
        currentFindings = filterInScope(currentFindings, entries).inScope;
      } catch (e) {
        if (!opts.quiet) console.error(yellow(`warn: scope evaluation skipped (${(e as Error).message})`));
      }
    }

    const diff = compareFindings(baselineFindings, currentFindings);

    if (opts.json) {
      process.stdout.write(JSON.stringify(diff, null, 2) + "\n");
      return;
    }

    if (!opts.quiet) {
      printDiffSummary(diff);
    }

    const md = renderDiffMarkdown(diff, { baselinePath: opts.baseline, currentPath: opts.current });

    if (opts.out) {
      const content = opts.html ? renderDiffHtml(diff, { baselinePath: opts.baseline, currentPath: opts.current }) : md;
      writeFileSync(opts.out, content, "utf8");
      if (!opts.quiet) console.error(green(`saved: ${opts.out}`));
    } else if (opts.html) {
      process.stdout.write(renderDiffHtml(diff, { baselinePath: opts.baseline, currentPath: opts.current }) + "\n");
    } else if (opts.quiet) {
      process.stdout.write(md + "\n");
    }
  });

const ws = program.command("workspace").description("manage multi-engagement workspaces");

ws.command("list")
  .description("list all engagement workspaces")
  .action(() => {
    const list = listWorkspaces();
    if (list.length === 0) {
      console.log(dim("no workspaces found — create one with `vapt workspace create <name>`"));
      return;
    }
    console.log(bold("\nEngagement Workspaces"));
    console.log(dim("─".repeat(50)));
    for (const w of list) {
      const activeMark = w.isActive ? green("● [active]") : dim("○");
      console.log(` ${activeMark} ${bold(w.name)} — ${w.engagement ?? "no engagement title"} (${w.targetCount} targets)`);
      console.log(`    ${dim(w.path)}`);
    }
    console.log("");
  });

ws.command("create <name>")
  .description("create a new engagement workspace")
  .option("-e, --engagement <title>", "client engagement title")
  .action((name: string, opts: { engagement?: string }) => {
    const dir = createWorkspace(name, { engagement: opts.engagement });
    console.error(green(`created workspace: ${name} at ${dir}`));
  });

ws.command("use <name>")
  .alias("switch")
  .description("switch active engagement workspace")
  .action((name: string) => {
    setActiveWorkspace(name);
    console.error(green(`active workspace switched to: ${name}`));
  });

ws.command("current")
  .description("display active engagement workspace")
  .action(() => {
    const active = getActiveWorkspace();
    if (!active) {
      console.log(dim("no active workspace selected"));
    } else {
      console.log(`Active workspace: ${green(bold(active))}`);
    }
  });

program.parseAsync().catch((e: unknown) => {
  console.error(red(e instanceof Error ? e.message : String(e)));
  process.exit(1);
});