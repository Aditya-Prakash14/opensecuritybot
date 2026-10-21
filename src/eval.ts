// Triage-accuracy harness: `npm run eval [-- <labeled.json> [<report.md>]]`.
// Runs the configured model (vapt setup / VAPT_LLM_*) over a labeled set and scores agreement.
// Each item costs one or two LLM calls. The shipped set in examples/eval/ is a small ILLUSTRATIVE
// seed — replace it with findings your team has labelled from real engagements before trusting
// any number here. Accuracy is a property of the model + the labels, not of this tool.
import { writeFileSync } from "node:fs";
import { readFileSync } from "node:fs";
import { severityRank } from "./findings.js";
import { llmIdentity } from "./llm.js";
import { triageFindingJson } from "./triage.js";
import type { Finding, Severity } from "./types.js";

interface Labeled {
  note?: string;
  finding: Finding;
  expected: { isLikelyTruePositive: boolean; severity: Severity };
}

const path = process.argv[2] ?? "examples/eval/labeled.json";
const reportPath = process.argv[3] ?? "eval-report.md";
const items = JSON.parse(readFileSync(path, "utf8")) as Labeled[];
// Scope is every labeled target: the eval measures triage, not scope filtering.
const scope = { engagement: "eval", targets: items.map((i) => i.finding.target) };
const { model, endpoint } = llmIdentity();

interface Row {
  id: string;
  gotTp: boolean;
  wantTp: boolean;
  gotSev: string;
  wantSev: Severity;
  sevDiff: number;
  note?: string;
  error?: string;
}

const rows: Row[] = [];
for (const item of items) {
  const { id } = item.finding;
  try {
    const r = await triageFindingJson(item.finding, { scope, cache: new Map() });
    rows.push({
      id,
      gotTp: r.triage.isLikelyTruePositive,
      wantTp: item.expected.isLikelyTruePositive,
      gotSev: r.triage.adjustedSeverity,
      wantSev: item.expected.severity,
      sevDiff: Math.abs(severityRank(r.triage.adjustedSeverity) - severityRank(item.expected.severity)),
      note: item.note,
    });
  } catch (e) {
    rows.push({ id, gotTp: false, wantTp: item.expected.isLikelyTruePositive, gotSev: "?", wantSev: item.expected.severity, sevDiff: 99, note: item.note, error: (e as Error).message });
  }
}

const scored = rows.filter((r) => !r.error);
const n = scored.length;
const verdictHits = scored.filter((r) => r.gotTp === r.wantTp).length;
const sevExact = scored.filter((r) => r.sevDiff === 0).length;
const sevNear = scored.filter((r) => r.sevDiff <= 1).length;
const errors = rows.filter((r) => r.error).length;

// Confusion matrix for the true/false-positive call (the decision that matters most).
const cm = {
  tpAsTp: scored.filter((r) => r.wantTp && r.gotTp).length,
  tpAsFp: scored.filter((r) => r.wantTp && !r.gotTp).length, // missed real finding — the dangerous error
  fpAsFp: scored.filter((r) => !r.wantTp && !r.gotTp).length,
  fpAsTp: scored.filter((r) => !r.wantTp && r.gotTp).length,
};
const pct = (k: number) => (n ? `${k}/${n} (${Math.round((k / n) * 100)}%)` : `${k}/0`);

for (const r of rows) {
  if (r.error) console.log(`! ${r.id}  error: ${r.error}`);
  else console.log(`${r.gotTp === r.wantTp ? "✓" : "✗"} ${r.id}  verdict ${r.gotTp ? "TP" : "FP"} (want ${r.wantTp ? "TP" : "FP"})  severity ${r.gotSev} (want ${r.wantSev})${r.note ? `  — ${r.note}` : ""}`);
}
console.log(`\nmodel ${model} via ${endpoint}  ·  ${n} scored, ${errors} error(s)`);
console.log(`verdict agreement   ${pct(verdictHits)}`);
console.log(`  missed real (want TP, got FP)   ${cm.tpAsFp}`);
console.log(`  false alarm (want FP, got TP)   ${cm.fpAsTp}`);
console.log(`severity exact      ${pct(sevExact)}`);
console.log(`severity within ±1  ${pct(sevNear)}`);

const md = [
  "# Triage evaluation",
  "",
  `_Model \`${model}\` via ${endpoint} · ${new Date().toISOString()} · set \`${path}\` (${items.length} cases)_`,
  "",
  "> Illustrative unless `" + path + "` holds labels from real engagements. Accuracy is a property of the model and the labels, not of opensecuritybot.",
  "",
  "| Metric | Result |",
  "| --- | --- |",
  `| Verdict agreement | ${pct(verdictHits)} |`,
  `| Missed real (want TP, got FP) | ${cm.tpAsFp} |`,
  `| False alarm (want FP, got TP) | ${cm.fpAsTp} |`,
  `| Severity exact | ${pct(sevExact)} |`,
  `| Severity within ±1 | ${pct(sevNear)} |`,
  `| Errors | ${errors} |`,
  "",
  "| Finding | Verdict (got/want) | Severity (got/want) | Note |",
  "| --- | --- | --- | --- |",
  ...rows.map((r) => `| ${r.id} | ${r.error ? "error" : `${r.gotTp ? "TP" : "FP"} / ${r.wantTp ? "TP" : "FP"}`} | ${r.error ? "—" : `${r.gotSev} / ${r.wantSev}`} | ${r.error ?? r.note ?? ""} |`),
  "",
].join("\n");
writeFileSync(reportPath, md);
console.log(`\nsaved ${reportPath}`);

// Non-zero exit if the model ever downgraded a real finding to a false positive — the error that matters.
if (cm.tpAsFp > 0) process.exitCode = 1;
