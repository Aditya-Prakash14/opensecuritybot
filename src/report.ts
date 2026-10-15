import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DATA_RULE, SYSTEM_PROMPT, dataTag } from "./agent-prompt.js";
import { findCveIds } from "./cve-cache.js";
import { chat } from "./llm.js";
import { type TriageCtx, triageFindingJson } from "./triage.js";
import type { CveEntry, Finding, TriageResult } from "./types.js";

const TRIAGE_CONCURRENCY = 4;

export interface ReportOutcome {
  markdown: string;
  failures: string[];
}

/** Triage every finding individually, then one synthesis pass assembles the REPORT MODE sections. */
export async function buildReport(
  findings: Finding[],
  ctx: TriageCtx,
  log?: (msg: string) => void,
): Promise<ReportOutcome> {
  const { results, failures } = await triageAll(findings, ctx, log);
  if (results.length === 0) throw new Error("no finding could be triaged — no report produced");
  const markdown = await synthesize(findings, results, failures, ctx, log);
  return { markdown, failures };
}

/** Write the report under the standard name scheme; returns the file path. */
export function saveReport(markdown: string, outDir: string): string {
  mkdirSync(outDir, { recursive: true });
  const file = join(outDir, `vapt-report-${new Date().toISOString().slice(0, 19).replace(/[:-]/g, "")}.md`);
  writeFileSync(file, markdown + "\n");
  return file;
}

/** Up to TRIAGE_CONCURRENCY calls in flight; results keep input (severity) order. */
async function triageAll(
  findings: Finding[],
  ctx: TriageCtx,
  log?: (msg: string) => void,
): Promise<{ results: TriageResult[]; failures: string[] }> {
  const results: (TriageResult | null)[] = new Array(findings.length).fill(null);
  const failures: string[] = [];
  let next = 0;
  const worker = async () => {
    while (next < findings.length) {
      const i = next++;
      const f = findings[i]!;
      log?.(`triaging ${i + 1}/${findings.length}: ${f.id} (${f.severity ?? "?"})`);
      try {
        results[i] = await triageFindingJson(f, ctx);
      } catch (e) {
        failures.push(`${f.id}: ${(e as Error).message}`);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(TRIAGE_CONCURRENCY, findings.length) }, worker));
  return { results: results.filter((r): r is TriageResult => r !== null), failures };
}

async function synthesize(
  findings: Finding[],
  results: TriageResult[],
  failures: string[],
  ctx: TriageCtx,
  log?: (msg: string) => void,
): Promise<string> {
  log?.(`synthesizing report from ${results.length} triage result(s)`);
  const compact = findings.map(({ raw: _raw, ...rest }) => rest); // the report must not carry evidence
  const entries = findCveIds(JSON.stringify({ findings: compact, results }))
    .map((id) => ctx.cache.get(id))
    .filter((e): e is CveEntry => Boolean(e));
  const failureNote = failures.length
    ? `\n\nThese findings could not be triaged (processing error) — list each under its severity flagged as "not triaged — processing error": ${failures.join("; ")}`
    : "";
  const content = await chat([
    { role: "system", content: SYSTEM_PROMPT },
    {
      role: "user",
      content: [
        "Compose the full VAPT report (REPORT MODE structure, sections 1-5) from the pre-computed triage results below. Use them as the substance of section 3 — do not re-triage. Group findings by severity.",
        "Markdown only. No exploit payloads, no raw traffic, no credentials — state that evidence is held in a separate access-controlled evidence log instead.",
        DATA_RULE + failureNote,
        dataTag("scope", ctx.scope),
        dataTag("findings", compact),
        dataTag("triage-results", results),
        dataTag("cve-cache", entries),
      ].join("\n\n"),
    },
  ]);
  return content.trim();
}