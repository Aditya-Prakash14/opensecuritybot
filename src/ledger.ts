import { createHash } from "node:crypto";
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
  prevHash?: string | null; // sha256 of the previous raw line; null for the first entry
}

const MAX_STEPS = 50;

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

function rawLines(path: string): string[] {
  try {
    return readFileSync(path, "utf8").split("\n").filter((l) => l.trim());
  } catch {
    return [];
  }
}

/** Append one JSONL audit entry chained to the previous line; throws on write failure so a missing audit record is visible. */
export function appendLedger(path: string, entry: LedgerEntry): void {
  mkdirSync(dirname(path), { recursive: true });
  const last = rawLines(path).at(-1);
  appendFileSync(path, JSON.stringify({ ...entry, prevHash: last === undefined ? null : sha256(last) }) + "\n");
}

/** "intact", "unchained" (pre-chain ledger) or "broken at line N" — an edited, removed or inserted line breaks the chain. */
// shortcut: lines deleted from the end are invisible to the chain; countersign the final hash elsewhere if that matters.
export function verifyLedger(path: string): string {
  const lines = rawLines(path);
  let chained = false;
  for (const [i, line] of lines.entries()) {
    let prev: unknown;
    try {
      prev = (JSON.parse(line) as LedgerEntry).prevHash;
    } catch {
      return `broken at line ${i + 1}`;
    }
    if (prev === undefined) {
      if (chained) return `broken at line ${i + 1}`;
      continue;
    }
    chained = true;
    if (prev !== (i === 0 ? null : sha256(lines[i - 1]!))) return `broken at line ${i + 1}`;
  }
  return chained ? "intact" : "unchained";
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
export function summarizeLedger(entries: LedgerEntry[], chain?: string): string {
  if (entries.length === 0) return "";
  const lines = entries.slice(0, MAX_STEPS).map(
    (e) =>
      `- ${e.ts} · ${e.skill} · ${e.target} · ${[e.tool, ...e.argv].map((a) => a.replace(/\s*\n\s*/g, " ")).join(" ")} · ${
        e.exitCode === null ? "aborted" : `exit ${e.exitCode}`
      } · ${e.durationMs}ms · ${formatBytes(e.outputBytes)} · sha256:${e.outputSha256.slice(0, 8)}`,
  );
  if (entries.length > MAX_STEPS) lines.push(`- … and ${entries.length - MAX_STEPS} more step(s)`);
  if (chain) lines.push(`- ledger hash chain: ${chain}`);
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
