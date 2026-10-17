#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline/promises";
import { Command } from "commander";
import { findCveIds, loadCveCache, prefetchMissingCves } from "./cve-cache.js";
import { deduplicateFindings, loadFindings } from "./findings.js";
import { loadLedger, summarizeLedger } from "./ledger.js";
import { TRIAGE_CONCURRENCY, buildReport, renderReportHtml, saveReport, saveReportHtml } from "./report.js";
import { runSkill } from "./runner.js";
import { filterInScope, loadScope, scopeEntries } from "./scope-guard.js";
import { startSession } from "./session.js";
import { ensureConfigured, runSetup } from "./setup.js";
import { getSkill, loadSkills, skillApplies } from "./skills.js";
import { type TriageCtx, sortBySeverity, triageFindingJson, triageFindingMarkdownStream } from "./triage.js";
import { VERSION } from "./version.js";
import { bold, coral, cyan, dim, findingHeader, green, red, severityColor, spinner, streamMarkdown, yellow } from "./ui.js";
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

/** Load + dedup + scope-filter. Anything outside scope.json is dropped here, before any LLM call. */
async function prepare(findingPath: string | string[], scopePath: string, cacheDir: string, quiet = false): Promise<Prepared> {
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
  const { unique, mergedCount } = deduplicateFindings(findings);
  const { inScope, outOfScope } = filterInScope(unique, entries);
  if (!quiet) {
    for (const s of skipped) console.error(dim(`skip: ${s}`));
    for (const d of duplicates) console.error(yellow(`warn: duplicate finding id — ${d}`));
    if (mergedCount > 0) console.error(dim(`merged: ${mergedCount} duplicate finding(s) across scanners`));
    for (const f of outOfScope) console.error(dim(`skip: out of scope — ${f.id} (${f.target})`));
  }
  if (inScope.length === 0) throw new Error("no in-scope findings to process");

  // Populate the CVE cache before triage: without it the model reasons blind and every cited CVE is flagged unverified.
  const cache = loadCveCache(resolvedCache);
  await prefetchMissingCves(findCveIds(JSON.stringify(inScope)), cache, resolvedCache, quiet ? undefined : (m) => console.error(dim(m)));

  return { scope, findings: sortBySeverity(inScope), cache };
}

const program = new Command();
program
  .name("vapt")
  .version(VERSION)
  .enablePositionalOptions() // subcommand flags (triage -f …) must not be swallowed by the program-level options
  .description("VAPT-Agent — triage, explain and report scanner findings (authorized engagements only)")
  .option("-f, --findings <path>", "findings JSON for the interactive session", "./findings.json")
  .option("-s, --scope <path>", "confirmed scope file", "./scope.json")
  .option("-c, --cache <dir>", "NVD cve-cache directory", "./cve-cache")
  .option("-o, --out <dir>", "report output directory", "./report")
  .action(async (opts: { findings: string; scope: string; cache: string; out: string }) => {
    await startSession(opts);
  });

program.addHelpText(
  "after",
  `
Examples:
  $ vapt setup                                connect a provider and model
  $ vapt init                                 scaffold scope.json, cve-cache/, report/
  $ vapt                                      interactive session
  $ vapt triage -f findings.json --json       machine-readable triage
  $ vapt report -f findings.json --html       full report (markdown + HTML)
  $ vapt diff -b before.json -c after.json    remediation delta

Engagement files: scope.json · findings.json · cve-cache/ · report/
Docs and limitations: README.md`,
);

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
    const { scope, findings, cache } = await prepare(opts.findings, opts.scope, opts.cache, opts.quiet);
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
    if (opts.json) {
      // Concurrent like report(); results keep severity order and failures are reported individually.
      const out: (TriageResult | null)[] = new Array(queue.length).fill(null);
      let next = 0;
      const worker = async () => {
        while (next < queue.length) {
          const i = next++;
          const f = queue[i]!;
          try {
            out[i] = await triageFindingJson(f, ctx);
            if (!opts.quiet) console.error(dim(`triaged ${f.id} (${f.severity ?? "?"})`));
          } catch (e) {
            failed++;
            console.error(red(`fail: ${f.id}: ${(e as Error).message}`));
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(TRIAGE_CONCURRENCY, queue.length) }, worker));
      results.push(...out.filter((r): r is TriageResult => r !== null));
      process.stdout.write(JSON.stringify(results, null, 2) + "\n");
    } else {
      for (const [i, f] of queue.entries()) {
        process.stdout.write(findingHeader(f, { index: i + 1, total: queue.length }));
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
    const { scope, findings, cache } = await prepare(opts.findings, opts.scope, opts.cache, opts.quiet);
    mkdirSync(opts.out, { recursive: true }); // fail fast: a bad --out path must not cost N+1 LLM calls
    if (!opts.quiet) console.error(dim(`plan: report over ${findings.length} in-scope finding(s) — per-finding triage, then synthesis`));
    const ledger = loadLedger(join(opts.out, "scan-ledger.jsonl"));
    if (!opts.quiet && ledger.length > 0) console.error(dim(`methodology: ${ledger.length} scan step(s) from the execution ledger`));
    const outcome = await buildReport(
      findings,
      { scope, cache },
      opts.quiet ? undefined : (msg) => console.error(dim(msg)),
      summarizeLedger(ledger),
    );
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
  .command("skills")
  .description("list the reviewed scan skills available to `vapt scan`")
  .option("--dir <dir>", "skills directory (default: VAPT_SKILLS_DIR or ./skills)")
  .action((opts: { dir?: string }) => {
    const skills = loadSkills(opts.dir);
    if (skills.length === 0) {
      console.log(dim("no skills found"));
      return;
    }
    console.log(bold("\nScan skills"));
    console.log(dim("─".repeat(50)));
    for (const s of skills) {
      const risk = s.risk === "active" ? red("active") : green("passive");
      console.log(` ${bold(s.name)}  ${risk} ${dim(`· ${s.appliesTo.join("/")} · ${s.steps.map((st) => st.tool).join(" + ")}`)}`);
      console.log(`   ${dim(s.description)}`);
    }
    console.log(dim("\nrun: vapt scan --skill <name> --target <scope entry>\n"));
  });

program
  .command("scan")
  .description("run a scope-pinned scan skill (reviewed argv only) and write normalized findings")
  .requiredOption("--skill <name>", "skill to run (see `vapt skills`)")
  .requiredOption("--target <target>", "one authorized target from scope.json")
  .option("-s, --scope <path>", "confirmed scope file", "./scope.json")
  .option("-o, --out <dir>", "findings output directory", "./findings")
  .option("--ledger <path>", "append-only execution ledger", "./report/scan-ledger.jsonl")
  .option("--dry-run", "print the exact commands without executing anything")
  .option("-y, --yes", "skip per-step confirmation (required in non-interactive runs)")
  .option("-q, --quiet", "suppress progress messages on stderr")
  .action(
    async (opts: {
      skill: string;
      target: string;
      scope: string;
      out: string;
      ledger: string;
      dryRun?: boolean;
      yes?: boolean;
      quiet?: boolean;
    }) => {
      const scope = loadScope(resolveWorkspacePath(opts.scope));
      const entries = scopeEntries(scope);
      const skill = getSkill(opts.skill);
      if (!skillApplies(skill, opts.target)) {
        throw new Error(`skill "${skill.name}" does not apply to ${opts.target} (applies to: ${skill.appliesTo.join(", ")})`);
      }
      if (!opts.dryRun && !opts.yes && !process.stdin.isTTY) {
        throw new Error("confirmation needs a TTY — pass --yes for non-interactive runs");
      }
      const rl = !opts.dryRun && !opts.yes ? createInterface({ input: process.stdin, output: process.stderr }) : undefined;
      try {
        const result = await runSkill({
          skill,
          target: opts.target,
          scopeEntries: entries,
          outDir: opts.out,
          ledgerPath: opts.ledger,
          yes: opts.yes ?? false,
          dryRun: opts.dryRun ?? false,
          log: (m) => {
            if (!opts.quiet) console.error(dim(m));
          },
          confirm: async (label, argv) => {
            if (!rl) return false;
            const answer = (await rl.question(`${cyan(`run ${label}`)}\n  ${dim(argv.join(" "))}\n${coral("execute?")} [y/N] `))
              .trim()
              .toLowerCase();
            return answer === "y" || answer === "yes";
          },
        });
        if (opts.dryRun) {
          if (!opts.quiet) console.error(dim("dry run — nothing executed, nothing written"));
          return;
        }
        if (result.findingsPath) {
          console.error(green(`saved: ${result.findingsPath}`));
          console.error(dim(`next: vapt report -f ${result.findingsPath} -s ${opts.scope}`));
        } else {
          console.error(yellow("no findings produced"));
        }
        if (result.failedSteps > 0) {
          console.error(red(`${result.failedSteps}/${skill.steps.length} step(s) failed`));
          process.exitCode = 1;
        }
      } finally {
        rl?.close();
      }
    },
  );

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

    if (opts.scope) {
      // A requested scope must be enforced: an unreadable one is an error, never a silent pass.
      const scope = loadScope(opts.scope);
      const entries = scopeEntries(scope);
      baselineFindings = filterInScope(baselineFindings, entries).inScope;
      currentFindings = filterInScope(currentFindings, entries).inScope;
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
      mkdirSync(dirname(opts.out), { recursive: true });
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