import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { appendLedger } from "./ledger.js";
import { normalizeOutput } from "./normalizers.js";
import { hostOf, isInScope } from "./scope-guard.js";
import { type Skill, renderArgs } from "./skills.js";

export interface ExecResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export type ExecFn = (tool: string, args: string[], timeoutMs: number) => Promise<ExecResult>;

export interface RunOptions {
  skill: Skill;
  target: string;
  scopeEntries: string[];
  outDir: string; // where findings JSON is written
  ledgerPath: string; // scan-ledger.jsonl
  yes: boolean; // skip per-step confirmation
  dryRun: boolean; // print commands, execute nothing, write nothing
  log: (msg: string) => void;
  confirm: (label: string, argv: string[]) => Promise<boolean>;
  lookup?: (host: string) => Promise<string[]>; // DNS resolver, injectable for tests
}

export interface RunResult {
  findingsPath?: string;
  findingsCount: number;
  failedSteps: number;
}

const METADATA_HOSTS = new Set(["169.254.169.254", "fd00:ec2::254", "metadata.google.internal"]);
const DEFAULT_TIMEOUT_MS = 120000;
const CAPTURE_BYTES = 10 * 1024 * 1024;

/** Metadata endpoints are refused even when listed in scope; then the scope is enforced. */
export function assertTargetAllowed(target: string, scopeEntries: string[]): void {
  if (isBlockedAddress(hostOf(target))) {
    throw new Error(`target "${target}" is a link-local/cloud metadata address — always refused`);
  }
  if (!isInScope(target, scopeEntries)) {
    throw new Error(`target "${target}" is outside the confirmed scope`);
  }
}

/** Link-local (cloud metadata lives here) and the known metadata literals. */
export function isBlockedAddress(addr: string): boolean {
  const a = addr.toLowerCase().replace(/^::ffff:/, "");
  return METADATA_HOSTS.has(a) || a.startsWith("169.254.") || /^fe[89ab][0-9a-f]:/.test(a);
}

async function defaultLookup(host: string): Promise<string[]> {
  try {
    const addrs = await Promise.race([
      lookup(host, { all: true }),
      new Promise<never>((_, reject) => setTimeout(reject, 5000).unref()),
    ]);
    return addrs.map((a) => a.address);
  } catch {
    return []; // unresolvable here means the tool cannot reach it either
  }
}

/** A hostname in scope must not resolve to a metadata/link-local address. */
// shortcut: checks DNS before each step but the tool resolves again (rebinding window); pin IPs if that matters.
export async function assertResolvesSafely(target: string, resolve: (host: string) => Promise<string[]> = defaultLookup): Promise<void> {
  const bad = (await resolve(hostOf(target))).find(isBlockedAddress);
  if (bad) throw new Error(`target "${target}" resolves to ${bad} (link-local/metadata) — always refused`);
}

/** Never rejects: spawn failures (e.g. ENOENT) resolve with exitCode null so they reach the ledger. */
export function defaultExec(tool: string, args: string[], timeoutMs: number): Promise<ExecResult> {
  return new Promise((resolve) => {
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(tool, args, { shell: false });
    } catch (e) {
      resolve({ exitCode: null, stdout: "", stderr: (e as Error).message });
      return;
    }
    let stdout = "";
    let stderr = "";
    let captured = 0;
    const collect = (stream: "stdout" | "stderr") => (chunk: Buffer) => {
      const room = CAPTURE_BYTES - captured;
      if (room <= 0) return;
      const buf = chunk.length > room ? chunk.subarray(0, room) : chunk;
      captured += buf.length;
      if (stream === "stdout") stdout += buf.toString("utf8");
      else stderr += buf.toString("utf8");
    };
    child.stdout.on("data", collect("stdout"));
    child.stderr.on("data", collect("stderr"));
    // shortcut: SIGKILL hits the direct child only; a grandchild holding the pipes delays close
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ exitCode: null, stdout: "", stderr: e.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ exitCode: code ?? null, stdout, stderr });
    });
  });
}

export async function runSkill(opts: RunOptions, exec?: ExecFn): Promise<RunResult> {
  const { skill, target, scopeEntries: entries, outDir, ledgerPath, yes, dryRun, log, confirm } = opts;
  assertTargetAllowed(target, entries);
  const run = exec ?? defaultExec;
  const records: Record<string, unknown>[] = [];
  let failedSteps = 0;

  for (let i = 1; i <= skill.steps.length; i++) {
    const step = skill.steps[i - 1]!;
    const argv = renderArgs(step.args, target);
    log(`[${i}/${skill.steps.length}] ${[step.tool, ...argv].join(" ")}`);
    if (dryRun) continue;
    if (!yes && !(await confirm(`step ${i}/${skill.steps.length}: ${step.tool}`, argv))) {
      throw new Error(`aborted by operator at step ${i}`);
    }
    await assertResolvesSafely(target, opts.lookup);
    const started = Date.now();
    const res = await run(step.tool, argv, step.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const durationMs = Date.now() - started;
    appendLedger(ledgerPath, {
      ts: new Date().toISOString(),
      skill: skill.name,
      target,
      step: i,
      tool: step.tool,
      argv,
      exitCode: res.exitCode,
      durationMs,
      outputSha256: createHash("sha256").update(res.stdout).digest("hex"),
      outputBytes: Buffer.byteLength(res.stdout),
    });
    if (res.exitCode !== 0) {
      failedSteps++;
      log(`step ${i} failed: ${res.stderr.slice(0, 200)}`);
      continue;
    }
    records.push(...normalizeOutput(skill.parsers[i - 1]!, res.stdout, target));
  }

  if (records.length === 0) return { findingsCount: 0, failedSteps };
  mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const findingsPath = join(outDir, `${skill.name}-${stamp}.json`);
  writeFileSync(findingsPath, JSON.stringify(records, null, 2));
  return { findingsPath, findingsCount: records.length, failedSteps };
}
