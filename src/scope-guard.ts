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
  if (out.size === 0) {
    throw new Error(
      "scope produced no matchable entries — expected string targets or objects with host/ip/url/domain/name/cidr/target keys",
    );
  }
  for (const entry of out) validateScopeEntry(entry);
  return [...out];
}

/** Validate CIDR notation when slash prefix is present on an IP target. */
export function validateScopeEntry(entry: string): void {
  const trimmed = unbracket(entry.trim());
  const slash = trimmed.lastIndexOf("/");
  if (slash < 0) return;
  const right = trimmed.slice(slash + 1);
  const left = trimmed.slice(0, slash);

  if (/^\d+$/.test(right)) {
    const prefix = Number(right);
    if (left.includes(":")) {
      if (prefix < 0 || prefix > 128) {
        throw new Error(`invalid scope target IPv6 CIDR "${entry}": prefix /${prefix} must be between 0 and 128`);
      }
      if (ipv6num(left) === null) {
        throw new Error(`invalid scope target IPv6 CIDR "${entry}": malformed IPv6 address "${left}"`);
      }
    } else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(left) || ipv4num(left) !== null) {
      if (prefix < 0 || prefix > 32) {
        throw new Error(`invalid scope target IPv4 CIDR "${entry}": prefix /${prefix} must be between 0 and 32`);
      }
      if (ipv4num(left) === null) {
        throw new Error(`invalid scope target IPv4 CIDR "${entry}": malformed IPv4 address "${left}"`);
      }
    }
  }
}

/** IPv6 ranges the matcher cannot handle yet — callers should warn instead of skipping silently. */
export function ipv6RangeEntries(entries: string[]): string[] {
  return entries.filter((e) => e.includes(":") && /^\[?[0-9a-f:]+\]?\/\d+$/i.test(e.trim()));
}

function hostOf(value: string): string {
  const v = value.trim();
  try {
    const u = new URL(v);
    if (u.hostname) return unbracket(u.hostname).toLowerCase();
  } catch {
    /* not a URL — fall through */
  }
  return unbracket(stripPort(v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split("/")[0]!)).toLowerCase();
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
    const v6cidr = ipv6CidrOf(entry.trim());
    if (v6cidr) {
      const ip6 = ipv6num(host);
      if (ip6 !== null && inIpv6Cidr(ip6, v6cidr)) return true;
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
  return unbracket(
    stripPort(
      entry
        .trim()
        .toLowerCase()
        .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
        .split("/")[0]!,
    ),
  );
}

/** Strip a trailing :port — but never from IPv6-shaped values (more than one colon). */
function stripPort(value: string): string {
  return (value.match(/:/g)?.length ?? 0) > 1 ? value : value.replace(/:\d+$/, "");
}

function unbracket(value: string): string {
  return value.replace(/^\[/, "").replace(/\]$/, "");
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

/** Parse an IPv6 address (full, compressed, or bracketed) into a 128-bit BigInt. */
function ipv6num(host: string): bigint | null {
  const addr = unbracket(host).toLowerCase();
  if (!addr.includes(":")) return null;
  const sides = addr.split("::");
  if (sides.length > 2) return null;
  let groups: string[];
  if (sides.length === 2) {
    const left = sides[0] ? sides[0].split(":") : [];
    const right = sides[1] ? sides[1].split(":") : [];
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    groups = [...left, ...Array(fill).fill("0"), ...right];
  } else {
    groups = addr.split(":");
  }
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

function ipv6CidrOf(entry: string): { net: bigint; prefix: number } | null {
  const trimmed = unbracket(entry.trim());
  const slash = trimmed.lastIndexOf("/");
  if (slash < 0) return null;
  const addr = trimmed.slice(0, slash);
  if (!addr.includes(":")) return null;
  const prefix = Number(trimmed.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null;
  const net = ipv6num(addr);
  if (net === null) return null;
  return { net, prefix };
}

function inIpv6Cidr(ip: bigint, cidr: { net: bigint; prefix: number }): boolean {
  if (cidr.prefix === 0) return true;
  const shift = BigInt(128 - cidr.prefix);
  return (ip >> shift) === (cidr.net >> shift);
}