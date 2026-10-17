import { readFileSync } from "node:fs";
import type { Finding } from "./types.js";

const TARGET_KEYS = ["target", "host", "url", "endpoint", "matched_at", "matchedAt", "matched-at", "asset"];
const ID_KEYS = ["id", "findingId", "template_id", "template-id", "_id", "alertRef", "pluginId"];
const MAX_RAW = 8000;

export interface LoadedFindings {
  findings: Finding[];
  skipped: string[];
  duplicates: string[];
}

function pickString(raw: Record<string, unknown>, keys: string[]): string | undefined {
  return keys.map((k) => raw[k]).find((v): v is string => typeof v === "string" && v.trim().length > 0);
}

function parseZapRisk(risk: unknown): string {
  if (typeof risk !== "string") return "info";
  const main = risk.split("(")[0]!.trim().toLowerCase();
  if (main.includes("high")) return "high";
  if (main.includes("medium")) return "medium";
  if (main.includes("low")) return "low";
  if (main.includes("informational") || main.includes("info")) return "info";
  return "low";
}

function parseRawFindingsData(content: string, path: string): unknown[] {
  try {
    const data = JSON.parse(content);
    if (Array.isArray(data)) return data;
    if (Array.isArray((data as any)?.findings)) return (data as any).findings;
    // Auto-detect OWASP ZAP JSON export
    if (Array.isArray((data as any)?.site)) {
      const zapAlerts: unknown[] = [];
      for (const s of (data as any).site) {
        if (Array.isArray(s?.alerts)) {
          for (const a of s.alerts) {
            const target = a?.instances?.[0]?.uri ?? s?.["@name"] ?? s?.name;
            zapAlerts.push({ ...a, target, title: a?.alert ?? a?.name, severity: parseZapRisk(a?.riskdesc ?? a?.risk) });
          }
        }
      }
      if (zapAlerts.length > 0) return zapAlerts;
    }
    throw new Error("expected a non-empty array or { \"findings\": [...] }");
  } catch (err) {
    // Attempt line-delimited JSON (Nuclei JSONL output)
    const lines = content.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length > 0 && lines.every((l) => l.startsWith("{") && l.endsWith("}"))) {
      try {
        return lines.map((l) => {
          const parsed = JSON.parse(l);
          if (parsed?.info && !parsed.title) {
            parsed.title = parsed.info.name ?? parsed.info.title;
            parsed.severity = parsed.severity ?? parsed.info.severity;
          }
          return parsed;
        });
      } catch {
        /* fall through to error */
      }
    }
    throw new Error(`${path}: not readable as JSON or JSONL (${(err as Error).message})`);
  }
}

const KEEP_KEYS = ["title", "description", "severity", "tool", "cve", "template_id", "template-id"];

function normalizeFinding(raw: unknown): { finding: Finding; autoId: boolean } | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const target = pickString(o, TARGET_KEYS);
  if (!target) return null;
  const picked = pickString(o, ID_KEYS);
  const finding: Finding = { id: picked ?? "", target };
  for (const k of KEEP_KEYS) if (o[k] !== undefined) finding[k] = o[k];
  // Bulk evidence lives only under `raw`, so MAX_RAW actually bounds what reaches a prompt.
  const size = JSON.stringify(raw).length;
  finding.raw = size > MAX_RAW ? `[evidence omitted: ${size} bytes]` : raw;
  return { finding, autoId: picked === undefined };
}

/** Identity for dedup and baseline/current matching: target + CVE, else target + title. */
export function findingSignature(f: Finding): string {
  const normTarget = (f.target || "").toLowerCase().replace(/\/+$/, "");
  const cveKey = Array.isArray(f.cve) && f.cve.length > 0 ? String(f.cve[0]).toUpperCase() : null;
  const titleKey = String(f.title || f.template_id || f.id || "").toLowerCase().trim();
  return `${normTarget}::${cveKey ?? titleKey}`;
}

/** critical=4 … info=0, unknown=-1. One ordering for sort, dedup and drift. */
export function severityRank(s?: string): number {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
    case "info":
    case "informational": return 0;
    default: return -1;
  }
}

/** Deduplicate findings across multiple scanners based on target + (cve || title || id). */
export function deduplicateFindings(findings: Finding[]): { unique: Finding[]; mergedCount: number } {
  const map = new Map<string, Finding>();
  let mergedCount = 0;

  for (const f of findings) {
    const sig = findingSignature(f);

    if (map.has(sig)) {
      const existing = map.get(sig)!;
      mergedCount++;
      if (f.tool && existing.tool && !existing.tool.includes(f.tool)) {
        existing.tool = `${existing.tool}, ${f.tool}`;
      }
      if (severityRank(f.severity) > severityRank(existing.severity)) {
        existing.severity = f.severity;
      }
    } else {
      map.set(sig, { ...f });
    }
  }

  return { unique: [...map.values()], mergedCount };
}

/**
 * Load and normalize one or more findings files (array, { "findings": [...] }, ZAP JSON, or Nuclei JSONL).
 * Auto-generated ids skip past any id the input already uses; duplicate input ids are reported across files.
 */
export function loadFindings(pathOrPaths: string | string[]): LoadedFindings {
  const paths = Array.isArray(pathOrPaths) ? pathOrPaths : [pathOrPaths];
  const allFindings: Finding[] = [];
  const allSkipped: string[] = [];
  const allDuplicates = new Set<string>();
  const used = new Set<string>();
  let nextAuto = 1;

  for (const path of paths) {
    let content: string;
    try {
      content = readFileSync(path, "utf8").trim();
    } catch (e) {
      throw new Error(`${path}: not readable (${(e as Error).message})`);
    }
    const arr = parseRawFindingsData(content, path);
    if (!Array.isArray(arr) || arr.length === 0) throw new Error(`${path}: expected a non-empty array or { "findings": [...] }`);

    const entries = arr.map((raw, i) => ({ i, normalized: normalizeFinding(raw) }));
    for (const { normalized } of entries) {
      if (!normalized || normalized.autoId) continue;
      if (used.has(normalized.finding.id)) allDuplicates.add(normalized.finding.id);
      used.add(normalized.finding.id);
    }

    for (const { i, normalized } of entries) {
      if (!normalized) {
        allSkipped.push(`${paths.length > 1 ? `${path} ` : ""}entry #${i + 1}: no target/host/url field`);
        continue;
      }
      const { finding, autoId } = normalized;
      if (autoId) {
        while (used.has(`F-${nextAuto}`)) nextAuto++;
        finding.id = `F-${nextAuto}`;
        used.add(finding.id);
      }
      allFindings.push(finding);
    }
  }

  return { findings: allFindings, skipped: allSkipped, duplicates: [...allDuplicates] };
}