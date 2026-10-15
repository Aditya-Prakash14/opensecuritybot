import { DATA_RULE, SYSTEM_PROMPT, dataTag } from "./agent-prompt.js";
import { findCveIds } from "./cve-cache.js";
import { chat, chatStream, parseJsonLoose } from "./llm.js";
import type { CveEntry, Finding, Scope, TriageResult } from "./types.js";
import { crossCheckCves, validateTriageResult } from "./verify.js";

export interface TriageCtx {
  scope: Scope;
  cache: Map<string, CveEntry>;
}

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 };

export function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => (RANK[String(a.severity ?? "").toLowerCase()] ?? 5) - (RANK[String(b.severity ?? "").toLowerCase()] ?? 5),
  );
}

function contextBlock(finding: Finding, ctx: TriageCtx): string {
  const entries = findCveIds(JSON.stringify(finding))
    .map((id) => ctx.cache.get(id))
    .filter((e): e is CveEntry => Boolean(e));
  return [dataTag("finding", finding), dataTag("scope", ctx.scope), dataTag("cve-cache", entries)].join("\n\n");
}

export async function triageFindingJson(finding: Finding, ctx: TriageCtx): Promise<TriageResult> {
  const content = await chat([
    { role: "system", content: SYSTEM_PROMPT },
    {
      role: "user",
      content: `Triage this single finding. Output ONLY one JSON object matching the OUTPUT SCHEMA, no prose, no code fences.\n\n${DATA_RULE}\n\n${contextBlock(finding, ctx)}`,
    },
  ]);
  const parsed = validateTriageResult(parseJsonLoose(content));
  // A model-echoed findingId is not authoritative — force the id of the finding we triaged.
  return crossCheckCves({ ...parsed, findingId: finding.id }, ctx.cache);
}

/** Streamed markdown triage, for humans reading a terminal. */
export function triageFindingMarkdownStream(finding: Finding, ctx: TriageCtx): AsyncGenerator<string> {
  return chatStream([
    { role: "system", content: SYSTEM_PROMPT },
    {
      role: "user",
      content: `Triage this single finding for a human reading a terminal. Render clean, scannable markdown: triage call and confidence, adjusted severity, OWASP mapping, explanation, remediation steps, and references (mark any unverified ones). No JSON.\n\n${DATA_RULE}\n\n${contextBlock(finding, ctx)}`,
    },
  ]);
}