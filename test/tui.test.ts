process.env.NO_COLOR = "1";
import assert from "node:assert/strict";
import test from "node:test";
import { findingHeader, formatTriageResult, renderHeroCard, stripAnsi } from "../src/ui.js";
import type { TriageResult } from "../src/types.js";

const finding = { id: "F-1", target: "https://example.com", title: "Old jQuery", severity: "high" };

test("tui: findingHeader shows KEV marker only when kev is set", () => {
  assert.ok(stripAnsi(findingHeader(finding, { kev: true })).includes("KEV"));
  assert.ok(!stripAnsi(findingHeader(finding)).includes("KEV"));
  assert.ok(!stripAnsi(findingHeader(finding, { index: 1, total: 2 })).includes("KEV"));
  assert.ok(stripAnsi(findingHeader(finding, { index: 1, total: 2 })).includes("1/2"));
});

test("tui: formatTriageResult renders the [verify] note as its own row, not inside reasoning", () => {
  const tr: TriageResult = {
    findingId: "F-1",
    triage: {
      isLikelyTruePositive: true,
      reasoning: "Matched CVE-2020-11022\n\n[verify] CVE-1999-0001 not found in NVD",
      adjustedSeverity: "medium",
      owaspCategory: "A06:2021",
    },
    explanation: "Outdated library",
    remediation: { summary: "Upgrade", steps: [], references: [] },
    confidence: "high",
    flaggedForManualReview: true,
  };
  const card = stripAnsi(formatTriageResult(tr));
  assert.match(card, /verify\s+CVE-1999-0001 not found in NVD/);
  assert.equal(card.match(/CVE-1999-0001/g)?.length, 1, "note printed once");
  assert.ok(!card.includes("[verify]"));
  assert.ok(card.includes("Matched CVE-2020-11022"));
});

test("tui: renderHeroCard shows kev count only when > 0", () => {
  assert.ok(stripAnsi(renderHeroCard({ inScopeCount: 3, kevCount: 2 })).includes("2 known exploited"));
  assert.ok(!stripAnsi(renderHeroCard({ inScopeCount: 3, kevCount: 0 })).includes("known exploited"));
  assert.ok(!stripAnsi(renderHeroCard({ inScopeCount: 3 })).includes("kev"));
});
