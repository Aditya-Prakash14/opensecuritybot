import { DATA_RULE, SYSTEM_PROMPT, dataTag } from "./agent-prompt.js";
import { findCveIds } from "./cve-cache.js";
import { severityRank } from "./findings.js";
import { type ChatMessage, chat, chatStream, parseJsonLoose } from "./llm.js";
import type { CveEntry, Finding, Scope, TriageResult } from "./types.js";
import { crossCheckCves, validateTriageResult } from "./verify.js";

export interface TriageCtx {
  scope: Scope;
  cache: Map<string, CveEntry>;
}

export function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function contextBlock(finding: Finding, ctx: TriageCtx): string {
  const entries = findCveIds(JSON.stringify(finding))
    .map((id) => ctx.cache.get(id))
    .filter((e): e is CveEntry => Boolean(e));
  return [dataTag("finding", finding), dataTag("scope", ctx.scope), dataTag("cve-cache", entries)].join("\n\n");
}

export async function triageFindingJson(finding: Finding, ctx: TriageCtx): Promise<TriageResult> {
  const messages: ChatMessage[] = [
    { role: "system", content: SYSTEM_PROMPT },
    {
      role: "user",
      content: `Triage this single finding. Output ONLY one JSON object matching the OUTPUT SCHEMA, no prose, no code fences.\n\n${DATA_RULE}\n\n${contextBlock(finding, ctx)}`,
    },
  ];
  const content = await chat(messages);
  let parsed: TriageResult;
  try {
    parsed = validateTriageResult(parseJsonLoose(content));
  } catch (e) {
    // One repair pass: a schema slip should not discard the whole triage.
    const repaired = await chat([
      ...messages,
      { role: "assistant", content },
      {
        role: "user",
        content: `That reply failed validation: ${(e as Error).message}. Return ONLY a corrected JSON object matching the OUTPUT SCHEMA — no prose, no code fences.`,
      },
    ]);
    parsed = validateTriageResult(parseJsonLoose(repaired));
  }
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