import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { findCveIds, loadCveCache } from "../src/cve-cache.js";
import { loadFindings } from "../src/findings.js";
import { chat, chatStream, parseJsonLoose } from "../src/llm.js";
import { buildReport } from "../src/report.js";
import { ipv6RangeEntries, isInScope, scopeEntries } from "../src/scope-guard.js";
import { triageFindingJson } from "../src/triage.js";
import { crossCheckCves, validateTriageResult } from "../src/verify.js";
import { box, stripAnsi, visibleLength } from "../src/ui.js";
import type { Finding, TriageResult } from "../src/types.js";

const ENTRIES = ["example.com", "*.api.example.com", "10.10.0.0/24"];

function cacheDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "vapt-cache-"));
  writeFileSync(
    join(dir, "CVE-2020-11022.json"),
    JSON.stringify({
      cve: {
        id: "CVE-2020-11022",
        descriptions: [{ lang: "en", value: "XSS in jQuery before 3.5.0" }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 6.1, baseSeverity: "MEDIUM" } }] },
      },
      references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2020-11022" }],
    }),
  );
  writeFileSync(join(dir, "misc.json"), JSON.stringify({ id: "CVE-2021-44228", description: "Log4Shell", cvss: 10 }));
  writeFileSync(join(dir, "CVE-1999-0001.json"), "{ not valid json");
  return dir;
}

test("scope: host, subdomain, wildcard, CIDR, out-of-scope", () => {
  assert.equal(isInScope("https://example.com/login?x=1", ENTRIES), true);
  assert.equal(isInScope("vpn.example.com:443", ENTRIES), true);
  assert.equal(isInScope("apps.api.example.com", ENTRIES), true);
  assert.equal(isInScope("10.10.0.55", ENTRIES), true);
  assert.equal(isInScope("http://10.10.1.7:8080", ENTRIES), false);
  assert.equal(isInScope("evil.example.net", ENTRIES), false);
  assert.equal(isInScope("notexample.com", ENTRIES), false);
});

test("scope: IPv6 hosts match, IPv6 ranges are reported, empty scope entries throw", () => {
  assert.equal(isInScope("http://[2001:db8::10]:8080/x", ["2001:db8::10"]), true);
  assert.equal(isInScope("2001:db8::1", ["2001:db8::1"]), true);
  assert.equal(isInScope("2001:db8::1", ["2001:db8::2"]), false);
  assert.deepEqual(ipv6RangeEntries(["2001:db8::/32", "example.com", "https://a.example.com/path"]), ["2001:db8::/32"]);
  assert.throws(() => scopeEntries({ targets: [{ hostname: "example.com" }] }), /no matchable entries/);
});

test("cve cache: eager files, lazy CVE-named files, malformed skipped", () => {
  const idx = loadCveCache(cacheDir());
  assert.equal(idx.get("CVE-2020-11022")?.cvss, 6.1); // parsed on demand from the filename index
  assert.equal(idx.get("CVE-2020-11022")?.severity, "MEDIUM");
  assert.equal(idx.get("CVE-2020-11022")?.references.length, 1);
  assert.equal(idx.get("CVE-2021-44228")?.description, "Log4Shell"); // flat file, parsed eagerly
  assert.equal(idx.get("CVE-2021-44228")?.cvss, 10);
  assert.equal(idx.has("CVE-1999-0001"), false); // malformed file named by CVE id
  assert.deepEqual(findCveIds("see cve-2020-11022 and CVE-2020-11022"), ["CVE-2020-11022"]);
});

test("findings: alias targets, generated ids avoid collisions, duplicates reported", () => {
  const dir = mkdtempSync(join(tmpdir(), "vapt-findings-"));
  const file = join(dir, "findings.json");
  writeFileSync(
    file,
    JSON.stringify([
      { matched_at: "https://a.example.com", template_id: "t-1" },
      { url: "https://b.example.com" },
      { id: "F-2", target: "https://c.example.com" },
      { title: "no target field" },
    ]),
  );
  const out = loadFindings(file);
  assert.equal(out.findings.length, 3);
  assert.equal(out.findings[0]!.id, "t-1");
  assert.equal(out.findings[0]!.target, "https://a.example.com");
  assert.equal(out.findings[1]!.id, "F-1"); // generated, skips past nothing taken
  assert.equal(out.findings[2]!.id, "F-2");
  assert.match(out.skipped[0]!, /#4/);
  assert.deepEqual(out.duplicates, []);

  writeFileSync(
    file,
    JSON.stringify([
      { id: "F-1", target: "https://a.example.com" },
      { id: "F-1", target: "https://b.example.com" },
      { target: "https://c.example.com" },
    ]),
  );
  const dup = loadFindings(file);
  assert.deepEqual(dup.duplicates, ["F-1"]);
  assert.equal(dup.findings[2]!.id, "F-2"); // F-1 is taken by the input

  assert.throws(() => loadFindings(join(dir, "missing.json")), /not readable/);
});

test("verify: valid result passes, bad enums throw", () => {
  const idx = loadCveCache(cacheDir());
  const tr: TriageResult = {
    findingId: "F-1",
    triage: { isLikelyTruePositive: true, reasoning: "version string matched CVE-2020-11022", adjustedSeverity: "medium", owaspCategory: "A06:2021" },
    explanation: "outdated library",
    remediation: { summary: "upgrade", steps: ["bump to 3.5.0"], references: [] },
    confidence: "high",
    flaggedForManualReview: false,
  };
  assert.equal(validateTriageResult(tr).findingId, "F-1");
  assert.throws(() => validateTriageResult({ ...tr, confidence: "very" }), /confidence/);
  assert.throws(() => validateTriageResult({ ...tr, triage: { ...tr.triage, adjustedSeverity: "severe" } }), /adjustedSeverity/);

  const clean = crossCheckCves(tr, idx);
  assert.equal(clean.flaggedForManualReview, false);

  const flagged = crossCheckCves({ ...tr, triage: { ...tr.triage, reasoning: "matched CVE-1999-0001" } }, idx);
  assert.equal(flagged.flaggedForManualReview, true);
  assert.match(flagged.triage.reasoning, /unverified — confirm manually: CVE-1999-0001/);
});

test("parseJsonLoose: fences and prose wrappers", () => {
  assert.deepEqual(parseJsonLoose('```json\n{"a":1}\n```'), { a: 1 });
  assert.deepEqual(parseJsonLoose('Here you go: {"a":1} done'), { a: 1 });
  assert.throws(() => parseJsonLoose("no json here"), /not parseable/);
});

function makeFinding(id: string): Finding {
  return { id, target: "https://example.com", title: id, severity: "medium", raw: { evidence: "SECRET-EVIDENCE" } };
}

function stubFetch(handler: (prompt: string) => string): { prompts: string[]; restore: () => void } {
  const prompts: string[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (_url: unknown, init: { body: string }) => {
    const prompt = JSON.parse(init.body).messages[1].content as string;
    prompts.push(prompt);
    return new Response(JSON.stringify({ choices: [{ message: { content: handler(prompt) } }] }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { prompts, restore: () => (globalThis.fetch = orig) };
}

const VALID_TRIAGE = JSON.stringify({
  findingId: "stub",
  triage: { isLikelyTruePositive: true, reasoning: "cites CVE-2020-11022", adjustedSeverity: "medium", owaspCategory: "A06:2021" },
  explanation: "e",
  remediation: { summary: "s", steps: ["one"], references: [] },
  confidence: "high",
  flaggedForManualReview: false,
});

test("report: triages each finding, then synthesizes; failures are noted", async (t) => {
  process.env.VAPT_LLM_MODEL = "stub";
  const { prompts, restore } = stubFetch((p) => {
    if (p.includes("Compose the full VAPT report")) return "REPORT MD";
    if (p.includes('"id": "F-B"')) return "garbage, not json";
    return VALID_TRIAGE;
  });
  t.after(restore);

  const out = await buildReport([makeFinding("F-A"), makeFinding("F-B")], {
    scope: { targets: ["example.com"] },
    cache: loadCveCache(cacheDir()),
  });
  assert.equal(prompts.length, 3); // 2 triage + 1 synthesis
  assert.equal(out.failures.length, 1);
  assert.match(out.failures[0]!, /F-B/);
  assert.equal(out.markdown, "REPORT MD");
  assert.match(prompts[2]!, /not triaged/);
  assert.ok(!prompts[2]!.includes("SECRET-EVIDENCE"), "synthesis prompt must not contain raw evidence");
});

test("report: all triage failures throw instead of producing an empty report", async (t) => {
  process.env.VAPT_LLM_MODEL = "stub";
  const { restore } = stubFetch(() => "garbage, not json");
  t.after(restore);
  await assert.rejects(
    () => buildReport([makeFinding("F-A")], { scope: { targets: ["example.com"] }, cache: new Map() }),
    /no finding could be triaged/,
  );
});

test("triage: findingId is forced from the input finding, not the model reply", async (t) => {
  process.env.VAPT_LLM_MODEL = "stub";
  const { restore } = stubFetch(() => JSON.stringify({ ...JSON.parse(VALID_TRIAGE), findingId: "wrong-id" }));
  t.after(restore);
  const out = await triageFindingJson(makeFinding("F-9"), { scope: { targets: ["example.com"] }, cache: new Map() });
  assert.equal(out.findingId, "F-9");
});

test("chat: retries once on 429, fails fast on other HTTP errors", async (t) => {
  process.env.VAPT_LLM_MODEL = "stub";
  const orig = globalThis.fetch;
  t.after(() => (globalThis.fetch = orig));
  const reply = (status: number, content: string) =>
    new Response(status === 200 ? JSON.stringify({ choices: [{ message: { content } }] }) : "denied", { status });

  let calls = 0;
  globalThis.fetch = (async () => (++calls === 1 ? reply(429, "") : reply(200, "ok"))) as typeof fetch;
  assert.equal(await chat([{ role: "user", content: "hi" }]), "ok");
  assert.equal(calls, 2);

  calls = 0;
  globalThis.fetch = (async () => (calls++, reply(400, ""))) as typeof fetch;
  await assert.rejects(() => chat([{ role: "user", content: "hi" }]), /LLM HTTP 400/);
  assert.equal(calls, 1);
});

test("chat: aborts stalled requests via VAPT_LLM_TIMEOUT_MS", async (t) => {
  process.env.VAPT_LLM_MODEL = "stub";
  process.env.VAPT_LLM_TIMEOUT_MS = "20";
  const orig = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = orig;
    delete process.env.VAPT_LLM_TIMEOUT_MS;
  });
  globalThis.fetch = ((_url: unknown, init: { signal: AbortSignal }) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason));
    })) as typeof fetch;
  await assert.rejects(() => chat([{ role: "user", content: "hi" }]), /timeout/i);
});

test("chatStream: yields SSE deltas until [DONE]", async (t) => {
  process.env.VAPT_LLM_MODEL = "stub";
  const orig = globalThis.fetch;
  t.after(() => (globalThis.fetch = orig));
  const sse = [
    'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n',
    'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n',
    "data: [DONE]\n\n",
  ];
  globalThis.fetch = (async () =>
    new Response(
      new ReadableStream({
        start(controller) {
          for (const frame of sse) controller.enqueue(new TextEncoder().encode(frame));
          controller.close();
        },
      }),
      { status: 200 },
    )) as typeof fetch;
  const chunks: string[] = [];
  for await (const chunk of chatStream([{ role: "user", content: "hi" }])) chunks.push(chunk);
  assert.equal(chunks.join(""), "Hello");
});

test("ui: box aligns borders and measures colored text", () => {
  const colored = "\x1b[31mred\x1b[0m";
  assert.equal(stripAnsi(colored), "red");
  assert.equal(visibleLength(colored), 3);

  const out = box(["short", colored], "title");
  const rows = out.split("\n");
  assert.equal(rows.length, 4);
  const widths = new Set(rows.map((r) => stripAnsi(r).length));
  assert.equal(widths.size, 1, "all box rows must render at the same width");
  assert.ok(stripAnsi(rows[0]!).includes(" title "));

  const plain = box(["only"]);
  assert.equal(new Set(plain.split("\n").map((r) => r.length)).size, 1);
});