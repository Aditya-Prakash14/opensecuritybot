import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadLedger } from "../src/ledger.js";
import { type ExecFn, type ExecResult, type RunOptions, assertTargetAllowed, defaultExec, runSkill } from "../src/runner.js";
import type { Skill } from "../src/skills.js";

interface Call {
  tool: string;
  args: string[];
  timeoutMs: number;
}

const SKILL: Skill = {
  name: "web-baseline",
  description: "runner test skill",
  appliesTo: ["url"],
  risk: "active",
  steps: [
    { tool: "httpx", args: ["-u", "{{target}}", "-json"], timeoutMs: 5000 },
    { tool: "nuclei", args: ["-u", "{{target}}", "-jsonl"] },
  ],
  parsers: ["httpx-jsonl", "nuclei-jsonl"],
};

const TARGET = "https://app.example.com";
const HTTPX_ARGV = ["-u", TARGET, "-json"];
const NUCLEI_ARGV = ["-u", TARGET, "-jsonl"];

function tmpdirPath(): string {
  return mkdtempSync(join(tmpdir(), "vapt-runner-"));
}

function stubExec(out: Record<string, ExecResult> = {}): { calls: Call[]; exec: ExecFn } {
  const calls: Call[] = [];
  const exec: ExecFn = async (tool, args, timeoutMs) => {
    calls.push({ tool, args, timeoutMs });
    return out[tool] ?? { exitCode: 0, stdout: "", stderr: "" };
  };
  return { calls, exec };
}

function opts(dir: string, over: Partial<RunOptions> = {}): RunOptions {
  return {
    skill: SKILL,
    target: TARGET,
    scopeEntries: ["*.example.com"],
    outDir: join(dir, "findings"),
    ledgerPath: join(dir, "scan-ledger.jsonl"),
    yes: true,
    dryRun: false,
    log: () => {},
    confirm: async () => true,
    lookup: async () => ["93.184.216.34"],
    ...over,
  };
}

const httpxStdout = '{"url":"https://app.example.com","status_code":200}\n';
const nucleiStdout = '{"template-id":"t-1","matched-at":"https://app.example.com/x","info":{"name":"Test","severity":"high"}}\n';

test("runner: dry-run executes nothing, confirms nothing, writes nothing", async () => {
  const dir = tmpdirPath();
  const { calls, exec } = stubExec();
  const logs: string[] = [];
  const result = await runSkill(opts(dir, { dryRun: true, log: (m) => logs.push(m) }), exec);
  assert.deepEqual(calls, []);
  assert.equal(result.findingsPath, undefined);
  assert.equal(result.findingsCount, 0);
  assert.equal(result.failedSteps, 0);
  assert.equal(existsSync(join(dir, "scan-ledger.jsonl")), false);
  assert.equal(existsSync(join(dir, "findings")), false);
  assert.deepEqual(logs, [
    `[1/2] httpx ${HTTPX_ARGV.join(" ")}`,
    `[2/2] nuclei ${NUCLEI_ARGV.join(" ")}`,
  ]);
});

test("runner: happy path writes merged findings and a two-entry ledger", async () => {
  const dir = tmpdirPath();
  const { calls, exec } = stubExec({
    httpx: { exitCode: 0, stdout: httpxStdout, stderr: "" },
    nuclei: { exitCode: 0, stdout: nucleiStdout, stderr: "" },
  });
  const result = await runSkill(opts(dir), exec);
  assert.equal(result.failedSteps, 0);
  assert.equal(result.findingsCount, 2);
  assert.match(result.findingsPath!, /web-baseline-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z\.json$/);

  const records = JSON.parse(readFileSync(result.findingsPath!, "utf8"));
  assert.equal(records.length, 2);
  assert.equal(records[0].tool, "httpx");
  assert.equal(records[1].tool, "nuclei");
  assert.equal(records[0].target, TARGET);
  assert.equal(records[1].severity, "high");

  const ledger = loadLedger(join(dir, "scan-ledger.jsonl"));
  assert.equal(ledger.length, 2);
  assert.deepEqual(ledger.map((e) => [e.step, e.tool, e.argv, e.exitCode]), [
    [1, "httpx", HTTPX_ARGV, 0],
    [2, "nuclei", NUCLEI_ARGV, 0],
  ]);
  assert.equal(ledger[0]!.skill, SKILL.name);
  assert.equal(ledger[0]!.target, TARGET);
  assert.equal(ledger[0]!.outputBytes, Buffer.byteLength(httpxStdout));
  assert.match(ledger[0]!.outputSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(calls.map((c) => c.timeoutMs), [5000, 120000]); // step default when unset
});

test("runner: out-of-scope target throws before any exec", async () => {
  const dir = tmpdirPath();
  const { calls, exec } = stubExec();
  await assert.rejects(runSkill(opts(dir, { target: "https://evil.example.net" }), exec), /outside the confirmed scope/);
  assert.deepEqual(calls, []);
  assert.equal(existsSync(join(dir, "scan-ledger.jsonl")), false);
});

test("runner: metadata endpoints are refused even when in scope", async () => {
  const dir = tmpdirPath();
  assert.throws(() => assertTargetAllowed("http://169.254.169.254/latest/meta-data/", ["169.254.0.0/16"]), /metadata/);
  assert.throws(() => assertTargetAllowed("METADATA.GOOGLE.INTERNAL:80", ["metadata.google.internal"]), /metadata/);
  assert.throws(() => assertTargetAllowed("[fd00:ec2::254]:8080", ["fd00:ec2::254"]), /metadata/);
  const { calls, exec } = stubExec();
  await assert.rejects(
    runSkill(opts(dir, { target: "169.254.169.254", scopeEntries: ["169.254.169.254"] }), exec),
    /metadata/,
  );
  assert.deepEqual(calls, []);
});

test("runner: a hostname resolving to link-local/metadata is refused before exec", async () => {
  const dir = tmpdirPath();
  const { calls, exec } = stubExec();
  await assert.rejects(runSkill(opts(dir, { lookup: async () => ["169.254.169.254"] }), exec), /resolves to 169\.254\.169\.254/);
  await assert.rejects(runSkill(opts(dir, { lookup: async () => ["::ffff:169.254.10.1"] }), exec), /link-local/);
  await assert.rejects(runSkill(opts(dir, { lookup: async () => ["fe80::1"] }), exec), /link-local/);
  assert.deepEqual(calls, []);
  assert.throws(() => assertTargetAllowed("169.254.1.1", ["169.254.0.0/16"]), /link-local/);
});

test("runner: declined confirmation aborts and writes no ledger", async () => {
  const dir = tmpdirPath();
  const { calls, exec } = stubExec();
  let seen: { label: string; argv: string[] } | null = null;
  await assert.rejects(
    runSkill(
      opts(dir, {
        yes: false,
        confirm: async (label, argv) => {
          seen = { label, argv };
          return false;
        },
      }),
      exec,
    ),
    /aborted by operator at step 1/,
  );
  assert.deepEqual(seen!.argv, HTTPX_ARGV);
  assert.deepEqual(calls, []);
  assert.equal(existsSync(join(dir, "scan-ledger.jsonl")), false);
});

test("runner: failing step is ledgered and counted, later steps still run", async () => {
  const dir = tmpdirPath();
  const { calls, exec } = stubExec({
    httpx: { exitCode: 1, stdout: "", stderr: "connection refused\n".repeat(20) },
    nuclei: { exitCode: 0, stdout: nucleiStdout, stderr: "" },
  });
  const logs: string[] = [];
  const result = await runSkill(opts(dir, { log: (m) => logs.push(m) }), exec);
  assert.equal(result.failedSteps, 1);
  assert.equal(result.findingsCount, 1);
  assert.equal(calls.length, 2);
  assert.ok(result.findingsPath && existsSync(result.findingsPath));
  assert.equal(JSON.parse(readFileSync(result.findingsPath!, "utf8"))[0].id, "t-1");

  const ledger = loadLedger(join(dir, "scan-ledger.jsonl"));
  assert.deepEqual(ledger.map((e) => [e.step, e.exitCode]), [
    [1, 1],
    [2, 0],
  ]);
  assert.equal(ledger[0]!.outputBytes, 0); // failed step had no stdout
  assert.match(logs.find((l) => l.startsWith("step 1 failed:"))!, /^step 1 failed: connection refused/);
  assert.ok(logs.find((l) => l.startsWith("step 1 failed:"))!.length <= "step 1 failed: ".length + 200);
});

test("defaultExec: missing binary resolves with null exitCode and never rejects", async () => {
  const res = await defaultExec("vapt-definitely-missing-binary", [], 1000);
  assert.equal(res.exitCode, null);
  assert.equal(res.stdout, "");
  assert.match(res.stderr, /ENOENT/);
});
