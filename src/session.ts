import { createInterface } from "node:readline/promises";
import { DATA_RULE, SYSTEM_PROMPT, dataTag } from "./agent-prompt.js";
import { loadCveCache } from "./cve-cache.js";
import { loadFindings } from "./findings.js";
import { type ChatMessage, chatStream } from "./llm.js";
import { buildReport, saveReport } from "./report.js";
import { filterInScope, loadScope, scopeEntries } from "./scope-guard.js";
import { type TriageCtx, sortBySeverity, triageFindingJson } from "./triage.js";
import { bold, cyan, dim, formatTriageResult, green, red, severityColor, spinner, streamMarkdown, yellow } from "./ui.js";
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

/** Interactive Claude-Code-style session: slash commands plus free-form questions about the queue. */
export async function startSession(opts: SessionOptions): Promise<void> {
  if (!process.stdin.isTTY) {
    throw new Error("interactive mode needs a TTY — for scripts use `vapt triage -f <findings> -s <scope.json>`");
  }

  const state: SessionState = { findings: [], cache: loadCveCache(opts.cache), results: new Map(), history: [] };
  const notes: string[] = [];

  try {
    state.scope = loadScope(opts.scope);
  } catch {
    notes.push(`${dim("scope:")} ${yellow("none")} — pass -s or run \`vapt init\``);
  }
  try {
    const loaded = loadFindings(opts.findings);
    if (state.scope) {
      const { inScope, outOfScope } = filterInScope(loaded.findings, scopeEntries(state.scope));
      state.findings = sortBySeverity(inScope);
      notes.push(
        outOfScope.length
          ? `${dim("findings:")} ${state.findings.length} in scope, ${yellow(`${outOfScope.length} skipped`)} (out of scope)`
          : `${dim("findings:")} ${state.findings.length} in scope`,
      );
    } else {
      state.findings = sortBySeverity(loaded.findings);
      notes.push(`${dim("findings:")} ${state.findings.length} loaded — ${yellow("no scope, /triage disabled")}`);
    }
  } catch {
    notes.push(`${dim("findings:")} ${yellow("none")} — run \`vapt init\` and drop scanner output at ${opts.findings}`);
  }

  process.stderr.write(`\n  ${bold(cyan("opensecuritybot"))} ${dim("· vapt-agent · authorized engagements only")}\n\n`);
  for (const n of notes) process.stderr.write(`  ${n}\n`);
  process.stderr.write(`  ${dim("/help for commands · /exit to quit · anything else asks the agent")}\n\n`);

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    while (true) {
      let line: string;
      try {
        line = (await rl.question(cyan("vapt> "))).trim();
      } catch {
        break; // stdin closed (Ctrl+D)
      }
      if (!line) continue;
      if (line === "/exit" || line === "/quit") break;
      try {
        if (line.startsWith("/")) await handleCommand(line, state, opts);
        else await askAgent(line, state);
      } catch (e) {
        process.stderr.write(red(`error: ${(e as Error).message}`) + "\n");
      }
    }
  } finally {
    rl.close();
  }
  process.stderr.write(dim("bye") + "\n");
}

async function handleCommand(line: string, state: SessionState, opts: SessionOptions): Promise<void> {
  const [cmd = "", ...rest] = line.slice(1).split(/\s+/);
  switch (cmd) {
    case "help":
      process.stdout.write(
        [
          `${bold("/triage")} [id]   triage all in-scope findings, or one by id`,
          `${bold("/findings")}       list the in-scope queue`,
          `${bold("/scope")}          show the confirmed scope targets`,
          `${bold("/report")}         compile the full VAPT report (re-triages all findings)`,
          `${bold("/help")} ${bold("/exit")}      this help / leave`,
          "",
          "Anything else is a question for the agent about the loaded engagement.",
        ].join("\n") + "\n",
      );
      return;

    case "scope": {
      if (!state.scope) {
        process.stderr.write(yellow("no scope.json loaded\n"));
        return;
      }
      process.stdout.write(`${bold("engagement")} ${state.scope.engagement ?? "—"}\n`);
      for (const e of scopeEntries(state.scope)) process.stdout.write(`  • ${e}\n`);
      return;
    }

    case "findings": {
      if (!state.findings.length) {
        process.stderr.write(yellow("no in-scope findings loaded\n"));
        return;
      }
      for (const f of state.findings) {
        const mark = state.results.has(f.id) ? green("triaged") : dim("queued ");
        process.stdout.write(
          `${f.id.padEnd(12)} ${severityColor(f.severity)(String(f.severity ?? "?").padEnd(9))} ${mark} ${f.title ?? f.target}\n`,
        );
      }
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
      for (const f of queue) {
        const sp = spinner(`triaging ${f.id} (${f.severity ?? "?"})...`);
        try {
          const r = await triageFindingJson(f, ctx);
          state.results.set(f.id, r);
          sp.stop();
          process.stdout.write(
            `\n${bold(f.id)} — ${f.title ?? f.target} ${severityColor(f.severity)(`[${f.severity ?? "unknown"}]`)}\n\n${formatTriageResult(r)}\n`,
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
      const outcome = await buildReport(state.findings, { scope: state.scope, cache: state.cache }, (m) =>
        process.stderr.write(dim(m) + "\n"),
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
  const compact = state.findings.slice(0, 60).map(({ raw: _raw, ...rest }) => rest);
  const context = [
    `Interactive session. ${state.findings.length} in-scope findings loaded, ${state.results.size} triaged so far. Answer from the engagement data below.`,
    DATA_RULE,
    dataTag("scope", state.scope ?? { note: "no scope.json loaded" }),
    dataTag("findings", compact),
    dataTag("triage-results", [...state.results.values()]),
  ].join("\n\n");
  const messages: ChatMessage[] = [
    { role: "system", content: SYSTEM_PROMPT },
    ...state.history.slice(-8),
    { role: "user", content: `${context}\n\n<question>\n${question}\n</question>` },
  ];
  process.stdout.write("\n");
  const answer = await streamMarkdown(chatStream(messages));
  state.history.push({ role: "user", content: question }, { role: "assistant", content: answer });
  process.stdout.write("\n");
}