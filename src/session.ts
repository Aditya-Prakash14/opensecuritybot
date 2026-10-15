import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { DATA_RULE, SYSTEM_PROMPT, dataTag } from "./agent-prompt.js";
import { loadCveCache } from "./cve-cache.js";
import { loadFindings } from "./findings.js";
import { type ChatMessage, chatStream } from "./llm.js";
import { buildReport, saveReport } from "./report.js";
import { filterInScope, loadScope, scopeEntries } from "./scope-guard.js";
import { ensureConfigured } from "./setup.js";
import { type TriageCtx, sortBySeverity, triageFindingJson } from "./triage.js";
import { bold, box, cyan, dim, formatTriageResult, green, red, severityColor, spinner, streamMarkdown, yellow } from "./ui.js";
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

/** Interactive Claude-Code-style session: welcome card, slash commands, streamed answers. */
export async function startSession(opts: SessionOptions): Promise<void> {
  if (!process.stdin.isTTY) {
    throw new Error("interactive mode needs a TTY — for scripts use `vapt triage -f <findings> -s <scope.json>`");
  }
  await ensureConfigured(); // first-run wizard when nothing is configured yet

  const state: SessionState = { findings: [], cache: loadCveCache(opts.cache), results: new Map(), history: [] };

  let scopeNote: string;
  try {
    state.scope = loadScope(opts.scope);
    scopeNote = `${dim("scope")}      ${state.scope.engagement ?? opts.scope}`;
  } catch {
    scopeNote = `${dim("scope")}      ${yellow("none — pass -s or run `vapt init`")}`;
  }

  let findingsNote: string;
  try {
    const loaded = loadFindings(opts.findings);
    if (state.scope) {
      const { inScope, outOfScope } = filterInScope(loaded.findings, scopeEntries(state.scope));
      state.findings = sortBySeverity(inScope);
      findingsNote = `${dim("findings")}   ${state.findings.length} in scope${outOfScope.length ? ` · ${yellow(`${outOfScope.length} skipped`)}` : ""}`;
    } else {
      state.findings = sortBySeverity(loaded.findings);
      findingsNote = `${dim("findings")}   ${state.findings.length} loaded · ${yellow("no scope, /triage disabled")}`;
    }
  } catch {
    findingsNote = `${dim("findings")}   ${yellow("none")} — drop scanner output at ${opts.findings}`;
  }

  process.stderr.write("\n" + box([scopeNote, findingsNote, `${dim("reports")}    ${opts.out}/`], "opensecuritybot · vapt-agent") + "\n");
  process.stderr.write(`  ${dim("authorized engagements only · /help for commands · /exit to quit")}\n\n`);

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const onSigint = () => {
    process.stderr.write("\n" + dim("(Use /exit to quit)") + "\n");
  };
  rl.on("SIGINT", onSigint);
  try {
    while (true) {
      let line: string;
      try {
        line = (await rl.question(cyan("❯ "))).trim();
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
    rl.removeListener("SIGINT", onSigint);
    rl.close();
  }
  process.stderr.write(dim("bye") + "\n");
}

async function handleCommand(line: string, state: SessionState, opts: SessionOptions): Promise<void> {
  const [cmd = "", ...rest] = line.slice(1).split(/\s+/);
  switch (cmd) {
    case "help":
      process.stdout.write(
        "\n" +
          box(
            [
              `${bold(padCmd("/triage [id]"))}triages all in-scope findings, or one by id`,
              `${bold(padCmd("/findings"))}the in-scope queue, severity-descending`,
              `${bold(padCmd("/scope"))}the confirmed engagement targets`,
              `${bold(padCmd("/report"))}compile the full VAPT report and save it`,
              `${bold(padCmd("/save [path]"))}persist triaged results & history to disk`,
              `${bold(padCmd("/load [path]"))}restore session state from disk`,
              `${bold(padCmd("/help"))}this help · ${bold("/exit")} leaves`,
              "",
              "Anything else is a question for the agent about the loaded engagement.",
            ],
            "commands",
          ) +
          "\n\n",
      );
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
        const sp = spinner(`Triaging ${f.id} (${f.severity ?? "?"})`);
        try {
          const r = await triageFindingJson(f, ctx);
          state.results.set(f.id, r);
          sp.stop();
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
  const sp = spinner("Thinking");
  try {
    const answer = await streamMarkdown(chatStream(messages), {
      onFirstChunk: () => {
        sp.stop();
        process.stdout.write(cyan("⏺") + " ");
      },
    });
    state.history.push({ role: "user", content: question }, { role: "assistant", content: answer });
  } finally {
    sp.stop();
  }
  process.stdout.write("\n");
}