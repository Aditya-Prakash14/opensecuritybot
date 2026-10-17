import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

export interface LedgerEntry {
  ts: string; // ISO timestamp
  skill: string;
  target: string;
  step: number; // 1-based
  tool: string;
  argv: string[]; // full argv after target substitution
  exitCode: number | null;
  durationMs: number;
  outputSha256: string; // sha256 of captured stdout
  outputBytes: number;
}

const MAX_STEPS = 50;

/** Append one JSONL audit entry; throws on write failure so a missing audit record is visible. */
export function appendLedger(path: string, entry: LedgerEntry): void {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(entry) + "\n");
}

/** Read the ledger in file order; missing/unreadable file is [], malformed lines are skipped. */
export function loadLedger(path: string): LedgerEntry[] {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return []; // ledger is optional evidence, absence is not an error
  }
  const entries: LedgerEntry[] = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (isEntry(parsed)) entries.push(parsed);
    } catch {
      /* skip malformed line, keep the rest of the audit trail */
    }
  }
  return entries;
}

/** Markdown bullet per step, in file order, for an LLM prompt; "" when there is nothing to say. */
export function summarizeLedger(entries: LedgerEntry[]): string {
  if (entries.length === 0) return "";
  const lines = entries.slice(0, MAX_STEPS).map(
    (e) =>
      `- ${e.ts} · ${e.skill} · ${e.target} · ${[e.tool, ...e.argv].map((a) => a.replace(/\s*\n\s*/g, " ")).join(" ")} · ${
        e.exitCode === null ? "aborted" : `exit ${e.exitCode}`
      } · ${e.durationMs}ms · ${formatBytes(e.outputBytes)} · sha256:${e.outputSha256.slice(0, 8)}`,
  );
  if (entries.length > MAX_STEPS) lines.push(`- … and ${entries.length - MAX_STEPS} more step(s)`);
  return lines.join("\n");
}

function isEntry(v: any): v is LedgerEntry {
  return typeof v?.ts === "string" && typeof v?.skill === "string" && typeof v?.target === "string";
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
