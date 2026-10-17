import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { type LedgerEntry, appendLedger, loadLedger, summarizeLedger } from "../src/ledger.js";

function tmpdirPath(): string {
  return mkdtempSync(join(tmpdir(), "vapt-ledger-"));
}

function entry(over: Partial<LedgerEntry> = {}): LedgerEntry {
  return {
    ts: "2026-10-17T12:00:00.000Z",
    skill: "http-baseline",
    target: "https://app.example.com",
    step: 1,
    tool: "httpx",
    argv: ["-json", "-u", "https://app.example.com"],
    exitCode: 0,
    durationMs: 812,
    outputSha256: "abcd1234ef567890",
    outputBytes: 12595,
    ...over,
  };
}

test("appendLedger creates missing parent dirs and loadLedger round-trips", () => {
  const path = join(tmpdirPath(), "report", "scan-ledger.jsonl");
  const written = entry();
  appendLedger(path, written);
  assert.deepEqual(loadLedger(path), [written]);
});

test("two appends leave two lines and two entries", () => {
  const path = join(tmpdirPath(), "ledger.jsonl");
  appendLedger(path, entry());
  appendLedger(path, entry({ step: 2, tool: "nuclei", exitCode: 1 }));
  assert.equal(readFileSync(path, "utf8").split("\n").filter(Boolean).length, 2);
  assert.deepEqual(loadLedger(path).map((e) => e.tool), ["httpx", "nuclei"]);
});

test("loadLedger on a missing path returns []", () => {
  assert.deepEqual(loadLedger(join(tmpdirPath(), "nope.jsonl")), []);
});

test("malformed lines are skipped, valid neighbours survive", () => {
  const path = join(tmpdirPath(), "ledger.jsonl");
  appendLedger(path, entry({ step: 1 }));
  appendFileSync(path, "{ not json\n");
  appendLedger(path, entry({ step: 3 }));
  assert.deepEqual(loadLedger(path).map((e) => e.step), [1, 3]);
});

test("summarizeLedger is empty for no entries", () => {
  assert.equal(summarizeLedger([]), "");
});

test("summarizeLedger renders one markdown bullet per entry", () => {
  assert.equal(
    summarizeLedger([entry()]),
    "- 2026-10-17T12:00:00.000Z · http-baseline · https://app.example.com · httpx -json -u https://app.example.com · exit 0 · 812ms · 12.3 KB · sha256:abcd1234",
  );
});

test("summarizeLedger marks a null exit code as aborted", () => {
  assert.match(summarizeLedger([entry({ exitCode: null })]), / · aborted · /);
});

test("summarizeLedger collapses newlines inside argv", () => {
  assert.match(summarizeLedger([entry({ argv: ["-H", "a\nb"] })]), /-H a b/);
});

test("summarizeLedger caps at 50 bullets and counts the rest", () => {
  const lines = summarizeLedger(Array.from({ length: 51 }, (_, i) => entry({ step: i + 1 }))).split("\n");
  assert.equal(lines.length, 51);
  assert.equal(lines[50], "- … and 1 more step(s)");
});
