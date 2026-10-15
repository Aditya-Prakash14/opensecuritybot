import { findCveIds } from "./cve-cache.js";
import type { CveEntry, Severity, TriageResult } from "./types.js";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const CONFIDENCES = ["high", "medium", "low"];

/** Structural gate for programmatic mode: a malformed model reply must never reach the consumer. */
export function validateTriageResult(x: unknown): TriageResult {
  const o = x as any;
  if (!o || typeof o !== "object") throw new Error("triage result is not an object");
  const errs: string[] = [];
  if (typeof o.findingId !== "string") errs.push("findingId must be a string");
  if (typeof o.explanation !== "string") errs.push("explanation must be a string");
  if (typeof o.triage?.isLikelyTruePositive !== "boolean") errs.push("triage.isLikelyTruePositive must be boolean");
  if (typeof o.triage?.reasoning !== "string") errs.push("triage.reasoning must be a string");
  if (!SEVERITIES.includes(o.triage?.adjustedSeverity)) errs.push(`triage.adjustedSeverity must be one of ${SEVERITIES.join("|")}`);
  if (!(o.triage?.owaspCategory === null || typeof o.triage?.owaspCategory === "string")) errs.push("triage.owaspCategory must be string|null");
  if (typeof o.remediation?.summary !== "string") errs.push("remediation.summary must be a string");
  if (!Array.isArray(o.remediation?.steps) || o.remediation.steps.some((s: unknown) => typeof s !== "string")) errs.push("remediation.steps must be string[]");
  if (!Array.isArray(o.remediation?.references) || o.remediation.references.some((r: unknown) => typeof r !== "string")) errs.push("remediation.references must be string[]");
  if (!CONFIDENCES.includes(o.confidence)) errs.push("confidence must be high|medium|low");
  if (typeof o.flaggedForManualReview !== "boolean") errs.push("flaggedForManualReview must be boolean");
  if (errs.length) throw new Error(`invalid triage result: ${errs.join("; ")}`);
  return o as TriageResult;
}

function stringsOf(r: TriageResult): string[] {
  return [
    r.triage.reasoning,
    ...(typeof r.triage.owaspCategory === "string" ? [r.triage.owaspCategory] : []),
    r.explanation,
    r.remediation.summary,
    ...r.remediation.steps,
    ...r.remediation.references,
  ];
}

/** Deterministic VERIFY step: any CVE ID the model cites that is not in the cache gets flagged, never trusted. */
export function crossCheckCves(result: TriageResult, index: Map<string, CveEntry>): TriageResult {
  const unverified = findCveIds(stringsOf(result).join("\n")).filter((id) => !index.has(id));
  if (unverified.length === 0) return result;
  return {
    ...result,
    flaggedForManualReview: true,
    triage: {
      ...result.triage,
      reasoning: `${result.triage.reasoning}\n\n[verify] unverified — confirm manually: ${unverified.join(", ")}`,
    },
  };
}