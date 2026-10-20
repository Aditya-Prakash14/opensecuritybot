// Triage accuracy against labeled findings: `npm run eval [-- path/to/labeled.json]`.
// Uses the configured model (vapt setup / VAPT_LLM_*). Each item costs one or two LLM calls.
import { readFileSync } from "node:fs";
import { severityRank } from "./findings.js";
import { triageFindingJson } from "./triage.js";
import type { Finding, Severity } from "./types.js";

interface Labeled {
  note?: string;
  finding: Finding;
  expected: { isLikelyTruePositive: boolean; severity: Severity };
}

const path = process.argv[2] ?? "examples/eval/labeled.json";
const items = JSON.parse(readFileSync(path, "utf8")) as Labeled[];
// Scope is every labeled target: the eval measures triage, not scope filtering.
const scope = { engagement: "eval", targets: items.map((i) => i.finding.target) };

let verdicts = 0;
let severities = 0;
let nearSeverities = 0;
let failed = 0;
for (const item of items) {
  const { id } = item.finding;
  try {
    const r = await triageFindingJson(item.finding, { scope, cache: new Map() });
    const okVerdict = r.triage.isLikelyTruePositive === item.expected.isLikelyTruePositive;
    const diff = Math.abs(severityRank(r.triage.adjustedSeverity) - severityRank(item.expected.severity));
    verdicts += okVerdict ? 1 : 0;
    severities += diff === 0 ? 1 : 0;
    nearSeverities += diff <= 1 ? 1 : 0;
    console.log(
      `${okVerdict ? "✓" : "✗"} ${id}  verdict ${r.triage.isLikelyTruePositive ? "TP" : "FP"} (want ${item.expected.isLikelyTruePositive ? "TP" : "FP"})  severity ${r.triage.adjustedSeverity} (want ${item.expected.severity})${item.note ? `  — ${item.note}` : ""}`,
    );
  } catch (e) {
    failed++;
    console.log(`! ${id}  error: ${(e as Error).message}`);
  }
}

const n = items.length;
const pct = (k: number) => `${k}/${n} (${Math.round((k / n) * 100)}%)`;
console.log(`\nverdict agreement   ${pct(verdicts)}`);
console.log(`severity exact      ${pct(severities)}`);
console.log(`severity within ±1  ${pct(nearSeverities)}`);
if (failed) console.log(`errors              ${failed}`);
