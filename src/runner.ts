import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { appendLedger } from "./ledger.js";
import { normalizeOutput } from "./normalizers.js";
import { isInScope } from "./scope-guard.js";
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
}

export interface RunResult {
  findingsPath?: string;
  findingsCount: number;
  failedSteps: number;
}

const METADATA_HOSTS = new Set(["169.254.169.254", "fd00:ec2::254", "metadata.google.internal"]);
const DEFAULT_TIMEOUT_MS = 120000;
const CAPTURE_BYTES = 10 * 1024 * 1024;

/** Host with scheme, path, port and brackets stripped; lowercased. */
function hostName(target: string): string {
  const v = target.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split("/")[0]!;
  if (v.startsWith("[")) {
    const end = v.indexOf("]");
    return v.slice(1, end < 0 ? undefined : end).toLowerCase();
  }
  // more than one colon means IPv6, never strip a "port" off it
  return ((v.match(/:/g)?.length ?? 0) > 1 ? v : v.replace(/:\d+$/, "")).toLowerCase();
}

/** Metadata endpoints are refused even when listed in scope; then the scope is enforced. */
export function assertTargetAllowed(target: string, scopeEntries: string[]): void {
  if (METADATA_HOSTS.has(hostName(target))) {
    throw new Error(`target "${target}" is a cloud metadata endpoint — always refused`);
  }
  if (!isInScope(target, scopeEntries)) {
    throw new Error(`target "${target}" is outside the confirmed scope`);
  }
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
