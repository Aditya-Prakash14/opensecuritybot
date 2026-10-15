import { readFileSync } from "node:fs";
import type { Finding, Scope } from "./types.js";

/** A scope file is mandatory: without a confirmed scope we refuse to process anything. */
export function loadScope(path: string): Scope {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`scope file not found or unreadable at ${path} — enforcement requires a confirmed scope.json`);
  }
  const targets = (raw as Scope)?.targets;
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new Error(`${path}: scope has no non-empty targets[] — refusing to run`);
  }
  return raw as Scope;
}

const TARGET_KEYS = ["host", "ip", "url", "domain", "name", "cidr", "target"];

/** Flatten scope.targets into matchable strings (strings stay as-is, objects contribute known keys). */
export function scopeEntries(scope: Scope): string[] {
  const out = new Set<string>();
  for (const t of scope.targets) {
    if (typeof t === "string") {
      out.add(t.trim());
    } else if (t && typeof t === "object") {
      for (const k of TARGET_KEYS) {
        const v = (t as Record<string, unknown>)[k];
        if (typeof v === "string" && v.trim()) out.add(v.trim());
      }
    }
  }
  out.delete("");
  return [...out];
}

export function hostOf(value: string): string {
  const v = value.trim();
  try {
    const u = new URL(v);
    if (u.hostname) return u.hostname.toLowerCase();
  } catch {
    /* not a URL — fall through */
  }
  return v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split("/")[0]!.replace(/:\d+$/, "").toLowerCase();
}

export function isInScope(target: string, entries: string[]): boolean {
  const host = hostOf(target);
  const lowerTarget = target.trim().toLowerCase();
  for (const entry of entries) {
    const cidr = cidrOf(entry.trim());
    if (cidr) {
      const ip = ipv4num(host);
      if (ip !== null && inCidr(ip, cidr)) return true;
      continue;
    }
    const pattern = hostPattern(entry);
    if (!pattern) continue;
    if (pattern.startsWith("*.")) {
      const base = pattern.slice(2);
      if (host === base || host.endsWith("." + base)) return true;
      continue;
    }
    if (host === pattern || host.endsWith("." + pattern)) return true;
    if (lowerTarget === entry.trim().toLowerCase()) return true; // non-host targets (exact strings)
  }
  return false;
}

export function filterInScope(findings: Finding[], entries: string[]): { inScope: Finding[]; outOfScope: Finding[] } {
  const inScope: Finding[] = [];
  const outOfScope: Finding[] = [];
  for (const f of findings) (isInScope(f.target, entries) ? inScope : outOfScope).push(f);
  return { inScope, outOfScope };
}

function hostPattern(entry: string): string {
  return entry
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
    .split("/")[0]!
    .replace(/:\d+$/, "");
}

function ipv4num(host: string): number | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

function cidrOf(entry: string): { net: number; prefix: number } | null {
  const m = entry.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) return null;
  const net = ipv4num(m[1]!);
  const prefix = Number(m[2]);
  if (net === null || prefix > 32) return null;
  return { net, prefix };
}

function inCidr(ip: number, cidr: { net: number; prefix: number }): boolean {
  const mask = cidr.prefix === 0 ? 0 : (0xffffffff << (32 - cidr.prefix)) >>> 0;
  return ((ip & mask) >>> 0) === ((cidr.net & mask) >>> 0);
}