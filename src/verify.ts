import { findCveIds } from "./cve-cache.js";
import type { CveEntry, Severity, TriageResult } from "./types.js";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const CONFIDENCES = ["high", "medium", "low"];

/** Structural gate for programmatic mode: a malformed model reply must never reach the consumer. */
export function validateTriageResult(x: unknown): TriageResult {
  const o = x as any;
  if (!o || typeof o !== "object") throw new Error("triage result is not an object");
  // Models often shout the enums ("HIGH"); normalize before the strict check.
  if (typeof o.triage?.adjustedSeverity === "string") o.triage.adjustedSeverity = o.triage.adjustedSeverity.toLowerCase();
  if (typeof o.confidence === "string") o.confidence = o.confidence.toLowerCase();
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

/**
 * Explicit CVSS score claims, e.g. "CVSS 8.8", "CVSS score: 9.8", "CVSSv3.1 7.5".
 * Vector strings ("CVSS:3.1/AV:N/...") carry no score and are stripped first.
 */
function cvssClaims(text: string): number[] {
  const plain = text.replace(/\bCVSS(?::| v?)?[23]\.\d\/[A-Z:\/.]+/gi, " ");
  const re = /\bcvss\s*(?:v?[23](?:\.\d)?)?\s*(?:base\s*)?(?:score)?\s*[:=]?\s*(\d{1,2}(?:\.\d)?)\b/gi;
  const out: number[] = [];
  for (let m = re.exec(plain); m; m = re.exec(plain)) {
    const n = Number(m[1]);
    if (n >= 0 && n <= 10) out.push(n);
  }
  return [...new Set(out)];
}

/** Deterministic VERIFY step: unverifiable CVE IDs, and scores that contradict the cached advisory, get flagged. */
export function crossCheckCves(result: TriageResult, index: Map<string, CveEntry>): TriageResult {
  const text = stringsOf(result).join("\n");
  const notes: string[] = [];

  const unverified = findCveIds(text).filter((id) => !index.has(id));
  if (unverified.length > 0) notes.push(`unverified — confirm manually: ${unverified.join(", ")}`);

  // Only compare when the text pins exactly one cached CVE and makes exactly one score claim — otherwise ambiguous.
  const cached = findCveIds(text)
    .map((id) => index.get(id))
    .filter((e): e is CveEntry => typeof e?.cvss === "number");
  const claims = cvssClaims(text);
  if (cached.length === 1 && claims.length === 1 && Math.abs(cached[0]!.cvss! - claims[0]!) > 0.05) {
    notes.push(`CVSS ${claims[0]} conflicts with ${cached[0]!.id} base score ${cached[0]!.cvss}`);
  }

  if (notes.length === 0) return result;
  return {
    ...result,
    flaggedForManualReview: true,
    triage: {
      ...result.triage,
      reasoning: `${result.triage.reasoning}\n\n[verify] ${notes.join("; ")}`,
    },
  };
}