import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { DATA_RULE, SYSTEM_PROMPT, dataTag } from "./agent-prompt.js";
import { findCveIds, loadCveCache, prefetchMissingCves } from "./cve-cache.js";
import { deduplicateFindings, loadFindings } from "./findings.js";
import { loadLedger, summarizeLedger } from "./ledger.js";
import { type ChatMessage, chatStream } from "./llm.js";
import { buildReport, saveReport } from "./report.js";
import { filterInScope, loadScope, scopeEntries } from "./scope-guard.js";
import { loadConfig } from "./config.js";
import { ensureConfigured } from "./setup.js";
import { type TriageCtx, sortBySeverity, triageFindingJson } from "./triage.js";
import {
  bold,
  box,
  coral,
  cyan,
  dim,
  formatTriageResult,
  green,
  red,
  renderAvatar,
  renderHeroCard,
  severityColor,
  spinner,
  streamMarkdown,
  truncate,
  yellow,
} from "./ui.js";
import type { CveEntry, Finding, Scope, TriageResult } from "./types.js";

export interface SessionOptions {
  findings: string;
  scope: string;
  cache: string;
  out: string;
}

interface SessionState {
  scope?: Scope;
  findings: Finding[];
  cache: Map<string, CveEntry>;
  results: Map<string, TriageResult>;
  history: ChatMessage[];
}

const padCmd = (s: string): string => s.padEnd(15);

const COMMANDS = ["triage", "findings", "scope", "report", "save", "load", "clear", "help", "exit", "quit"];
const ALIASES: Record<string, string> = { t: "triage", f: "findings", r: "report", s: "scope", "?": "help" };

/** Tab completion for slash commands and finding ids after `/triage`. */
export function slashCompleter(line: string, ids: string[]): [string[], string] {
  const command = line.match(/^\/([a-z]*)$/);
  if (command) return [COMMANDS.filter((c) => c.startsWith(command[1]!)).map((c) => "/" + c), line];
  const triageId = line.match(/^\/triage\s+(\S*)$/);
  if (triageId) return [ids.filter((id) => id.startsWith(triageId[1]!)), line];
  return [[], line];
}

/** Interactive Claude-Code-style session: welcome card, slash commands, streamed answers. */
export async function startSession(opts: SessionOptions): Promise<void> {
  if (!process.stdin.isTTY) {
    throw new Error("interactive mode needs a TTY — for scripts use `vapt triage -f <findings> -s <scope.json>`");
  }
  await ensureConfigured(); // first-run wizard when nothing is configured yet

  const cfg = loadConfig();
  const state: SessionState = { findings: [], cache: loadCveCache(opts.cache), results: new Map(), history: [] };
  let outOfScopeCount = 0;

  let scopeNote: string | undefined;
  let findingsNote: string | undefined;
  try {
    state.scope = loadScope(opts.scope);
  } catch (e) {
    scopeNote = (e as Error).message;
  }

  try {
    const loaded = loadFindings(opts.findings);
    const { unique, mergedCount } = deduplicateFindings(loaded.findings);
    if (mergedCount > 0) process.stderr.write(dim(`merged: ${mergedCount} duplicate finding(s) across scanners`) + "\n");
    // No confirmed scope = no findings: nothing unverified may reach the model.
    if (state.scope) {
      const { inScope, outOfScope } = filterInScope(unique, scopeEntries(state.scope));
      state.findings = sortBySeverity(inScope);
      outOfScopeCount = outOfScope.length;
    }
  } catch (e) {
    findingsNote = (e as Error).message;
  }

  const severityCounts: Record<string, number> = {};
  for (const f of state.findings) {
    const sev = String(f.severity ?? "info").toLowerCase();
    const key = sev === "informational" ? "info" : sev;
    severityCounts[key] = (severityCounts[key] ?? 0) + 1;
  }

  process.stderr.write("\n" + renderAvatar() + "\n\n");
  process.stderr.write(
    renderHeroCard({
      engagement: state.scope?.engagement,
      inScopeCount: state.findings.length,
      skippedCount: outOfScopeCount,
      reportsDir: opts.out,
      model: cfg?.model,
      provider: cfg?.provider,
      severityCounts,
    }) + "\n",
  );
  process.stderr.write(`  ${dim("authorized engagements only · tab completes · /help for commands · /exit to quit")}\n`);
  if (scopeNote) process.stderr.write(`  ${yellow(`note: ${scopeNote}`)}\n`);
  if (findingsNote) process.stderr.write(`  ${yellow(`note: ${findingsNote}`)}\n`);
  if (!state.findings.length) {
    process.stderr.write(
      `  ${dim("hint: add a confirmed scope.json and drop scanner output at findings.json (or pass -f), then restart")}\n`,
    );
  }
  process.stderr.write("\n");

  // Populate the CVE cache before the first question: without it the model reasons blind and every cited CVE is flagged unverified.
  await prefetchMissingCves(findCveIds(JSON.stringify(state.findings)), state.cache, opts.cache, (m) =>
    process.stderr.write(dim(m) + "\n"),
  );

  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
    completer: (line: string) => slashCompleter(line, state.findings.map((f) => f.id)),
  });
  const onSigint = () => {
    process.stderr.write("\n" + dim("(Use /exit to quit)") + "\n");
  };
  rl.on("SIGINT", onSigint);
  try {
    while (true) {
      let line: string;
      try {
        const engTitle = state.scope?.engagement ?? "engagement";
        const promptBar = dim(`╭─ 🛡️  ${engTitle} · ${state.results.size}/${state.findings.length} triaged · ${cfg?.model ?? "agent"} ─`);
        process.stderr.write(`${promptBar}\n`);
        line = (await rl.question(coral("╰─❯ "))).trim();
      } catch {
        break; // stdin closed (Ctrl+D)
      }
      if (!line) continue;
      if (line === "/exit" || line === "/quit" || line === "/q") break;
      try {
        if (line.startsWith("/")) await handleCommand(line, state, opts);
        else await askAgent(line, state);
      } catch (e) {
        process.stderr.write(red(`error: ${(e as Error).message}`) + "\n");
      }
    }
  } finally {
    rl.removeListener("SIGINT", onSigint);
    rl.close();
  }
  process.stderr.write(dim("bye") + "\n");
}

async function handleCommand(line: string, state: SessionState, opts: SessionOptions): Promise<void> {
  const [rawCmd = "", ...rest] = line.slice(1).split(/\s+/);
  const cmd = ALIASES[rawCmd] ?? rawCmd;
  switch (cmd) {
    case "help":
      process.stdout.write(
        "\n" +
          box(
            [
              bold("Engagement"),
              `${dim(padCmd("/findings"))}in-scope queue, triaged/queued`,
              `${dim(padCmd("/scope"))}confirmed engagement targets`,
              "",
              bold("Analysis"),
              `${dim(padCmd("/triage [id]"))}triage the queue, or one finding by id`,
              `${dim(padCmd("/report"))}compile and save the full VAPT report`,
              "",
              bold("Session"),
              `${dim(padCmd("/save [path]"))}persist triaged results & history`,
              `${dim(padCmd("/load [path]"))}restore a saved session`,
              `${dim(padCmd("/clear"))}clear the screen`,
              `${dim(padCmd("/help"))}this help`,
              `${dim(padCmd("/exit"))}leave`,
              "",
              dim("Tab completes commands and finding ids · anything else asks the agent."),
            ],
            "commands",
          ) +
          "\n\n",
      );
      return;

    case "clear":
      process.stdout.write("\x1b[2J\x1b[3J\x1b[H");
      return;

    case "save": {
      const targetPath = rest[0] || join(opts.out, "session-state.json");
      try {
        mkdirSync(opts.out, { recursive: true });
        const payload = {
          savedAt: new Date().toISOString(),
          results: [...state.results.entries()],
          history: state.history,
        };
        writeFileSync(targetPath, JSON.stringify(payload, null, 2) + "\n");
        process.stdout.write(green(`saved session state (${state.results.size} result(s)) to ${targetPath}`) + "\n");
      } catch (e) {
        process.stderr.write(red(`failed to save session: ${(e as Error).message}`) + "\n");
      }
      return;
    }

    case "load": {
      const targetPath = rest[0] || join(opts.out, "session-state.json");
      try {
        const raw = JSON.parse(readFileSync(targetPath, "utf8"));
        let count = 0;
        if (Array.isArray(raw?.results)) {
          for (const [k, v] of raw.results) {
            state.results.set(k, v);
            count++;
          }
        }
        if (Array.isArray(raw?.history)) {
          state.history = raw.history;
        }
        process.stdout.write(green(`loaded session state (${count} result(s)) from ${targetPath}`) + "\n");
      } catch (e) {
        process.stderr.write(red(`failed to load session: ${(e as Error).message}`) + "\n");
      }
      return;
    }

    case "scope": {
      if (!state.scope) {
        process.stderr.write(yellow("no scope.json loaded\n"));
        return;
      }
      const rows = [`${bold("engagement")} ${state.scope.engagement ?? "—"}`, ""];
      for (const e of scopeEntries(state.scope)) rows.push(`• ${e}`);
      process.stdout.write("\n" + box(rows, "scope") + "\n\n");
      return;
    }

    case "findings": {
      if (!state.findings.length) {
        process.stderr.write(yellow("no in-scope findings loaded\n"));
        return;
      }
      const width = process.stdout.columns ?? 100;
      const triaged = state.findings.filter((f) => state.results.has(f.id)).length;
      process.stdout.write(
        `\n${dim(`${state.findings.length} in-scope · ${triaged} triaged · ${state.findings.length - triaged} queued`)}\n`,
      );
      for (const f of state.findings) {
        const mark = state.results.has(f.id) ? green("triaged") : dim("queued ");
        const label = truncate(String(f.title ?? f.target), Math.max(20, width - 36));
        process.stdout.write(
          `${f.id.padEnd(12)} ${severityColor(f.severity)(String(f.severity ?? "?").padEnd(9))} ${mark} ${label}\n`,
        );
      }
      process.stdout.write("\n");
      return;
    }

    case "triage": {
      if (!state.scope) {
        process.stderr.write(yellow("no scope.json loaded — refusing to triage\n"));
        return;
      }
      const queue = rest[0] ? state.findings.filter((f) => f.id === rest[0]) : state.findings;
      if (!queue.length) {
        process.stderr.write(yellow(rest[0] ? `no in-scope finding with id ${rest[0]}\n` : "no in-scope findings loaded\n"));
        return;
      }
      const ctx: TriageCtx = { scope: state.scope, cache: state.cache };
      for (const [i, f] of queue.entries()) {
        const started = Date.now();
        const sp = spinner(`Triaging ${f.id} (${f.severity ?? "?"}) ${dim(`[${i + 1}/${queue.length}]`)}`);
        try {
          const r = await triageFindingJson(f, ctx);
          state.results.set(f.id, r);
          sp.stop(green(`✓ ${f.id} triaged in ${((Date.now() - started) / 1000).toFixed(1)}s`));
          process.stdout.write(
            `\n${cyan("⏺")} ${bold(f.id)} — ${f.title ?? f.target} ${severityColor(f.severity)(`[${f.severity ?? "unknown"}]`)}\n\n${formatTriageResult(r)}\n`,
          );
        } catch (e) {
          sp.stop(red(`fail: ${f.id}: ${(e as Error).message}`));
        }
      }
      return;
    }

    case "report": {
      if (!state.scope) {
        process.stderr.write(yellow("no scope.json loaded — refusing to report\n"));
        return;
      }
      if (!state.findings.length) {
        process.stderr.write(yellow("no in-scope findings loaded\n"));
        return;
      }
      const ledger = loadLedger(join(opts.out, "scan-ledger.jsonl"));
      if (ledger.length > 0) {
        process.stderr.write(dim(`methodology: ${ledger.length} scan step(s) from the execution ledger`) + "\n");
      }
      const outcome = await buildReport(
        state.findings,
        { scope: state.scope, cache: state.cache },
        (m) => process.stderr.write(dim(m) + "\n"),
        summarizeLedger(ledger),
      );
      process.stdout.write(outcome.markdown + "\n");
      try {
        const file = saveReport(outcome.markdown, opts.out);
        process.stderr.write(green(`saved: ${file}`) + "\n");
      } catch (e) {
        process.stderr.write(yellow(`warn: could not save report (${(e as Error).message}) — printed above only`) + "\n");
      }
      if (outcome.failures.length) {
        process.stderr.write(
          red(`${outcome.failures.length}/${state.findings.length} finding(s) failed triage: ${outcome.failures.join("; ")}`) + "\n",
        );
      }
      return;
    }

    default:
      process.stderr.write(yellow(`unknown command /${cmd} — try /help`) + "\n");
  }
}

async function askAgent(question: string, state: SessionState): Promise<void> {
  const shown = state.findings.slice(0, 60);
  const compact = shown.map(({ raw: _raw, ...rest }) => rest);
  const results = shown.map((f) => state.results.get(f.id)).filter((r): r is TriageResult => Boolean(r));
  const omitted = state.findings.length - shown.length;
  const context = [
    `Interactive session. ${state.findings.length} in-scope findings loaded, ${state.results.size} triaged so far.${omitted > 0 ? ` Only the first ${shown.length} are included below (${omitted} omitted for context size).` : ""} Answer from the engagement data below.`,
    DATA_RULE,
    dataTag("scope", state.scope ?? { note: "no scope.json loaded" }),
    dataTag("findings", compact),
    dataTag("triage-results", results),
  ].join("\n\n");
  const messages: ChatMessage[] = [
    { role: "system", content: SYSTEM_PROMPT },
    ...state.history.slice(-8),
    { role: "user", content: `${context}\n\n<question>\n${question}\n</question>` },
  ];
  process.stdout.write("\n");
  const sp = spinner("Thinking");
  try {
    const answer = await streamMarkdown(chatStream(messages), {
      onFirstChunk: () => {
        sp.stop();
        process.stdout.write(`${coral("⏺")} ${bold("opensecuritybot")}\n\n`);
      },
    });
    state.history.push({ role: "user", content: question }, { role: "assistant", content: answer });
  } finally {
    sp.stop();
  }
  process.stdout.write("\n");
}