import { readFileSync } from "node:fs";
import type { Finding } from "./types.js";

const TARGET_KEYS = ["target", "host", "url", "endpoint", "matched_at", "matchedAt", "asset"];
const ID_KEYS = ["id", "findingId", "template_id", "_id", "alertRef"];
const MAX_RAW = 8000;

export interface LoadedFindings {
  findings: Finding[];
  skipped: string[];
  duplicates: string[];
}

function pickString(raw: Record<string, unknown>, keys: string[]): string | undefined {
  return keys.map((k) => raw[k]).find((v): v is string => typeof v === "string" && v.trim().length > 0);
}

function normalizeFinding(raw: unknown): { finding: Finding; autoId: boolean } | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const target = pickString(o, TARGET_KEYS);
  if (!target) return null;
  const picked = pickString(o, ID_KEYS);
  const size = JSON.stringify(raw).length;
  return {
    finding: { ...o, id: picked ?? "", target, raw: size > MAX_RAW ? `[evidence omitted: ${size} bytes]` : raw },
    autoId: picked === undefined,
  };
}

/**
 * Load and normalize a findings file (array or { "findings": [...] }).
 * Auto-generated ids skip past any id the input already uses; duplicate input ids are reported.
 */
export function loadFindings(path: string): LoadedFindings {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`${path}: not readable as JSON (${(e as Error).message})`);
  }
  const arr = Array.isArray(data) ? data : (data as { findings?: unknown })?.findings;
  if (!Array.isArray(arr) || arr.length === 0) throw new Error(`${path}: expected a non-empty array or { "findings": [...] }`);

  const entries = arr.map((raw, i) => ({ i, normalized: normalizeFinding(raw) }));

  const used = new Set<string>();
  const duplicates = new Set<string>();
  for (const { normalized } of entries) {
    if (!normalized || normalized.autoId) continue;
    if (used.has(normalized.finding.id)) duplicates.add(normalized.finding.id);
    used.add(normalized.finding.id);
  }

  const findings: Finding[] = [];
  const skipped: string[] = [];
  let nextAuto = 1;
  for (const { i, normalized } of entries) {
    if (!normalized) {
      skipped.push(`entry #${i + 1}: no target/host/url field`);
      continue;
    }
    const { finding, autoId } = normalized;
    if (autoId) {
      while (used.has(`F-${nextAuto}`)) nextAuto++;
      finding.id = `F-${nextAuto}`;
      used.add(finding.id);
    }
    findings.push(finding);
  }
  return { findings, skipped, duplicates: [...duplicates] };
}