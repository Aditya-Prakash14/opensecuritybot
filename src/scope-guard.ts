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
  const scope = raw as Scope;
  const targets = scope?.targets;
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new Error(`${path}: scope has no non-empty targets[] — refusing to run`);
  }
  if (scope.exclude !== undefined && (!Array.isArray(scope.exclude) || scope.exclude.some((e) => typeof e !== "string"))) {
    throw new Error(`${path}: exclude must be an array of strings`);
  }
  for (const e of scope.exclude ?? []) {
    // Matching is per host: "acme.com/admin" would silently exclude all of acme.com.
    const rest = e.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    if (rest.includes("/") && !/^[^/]+\/\d{1,3}$/.test(rest)) {
      throw new Error(`${path}: exclude entry "${e}" has a path — exclusions match whole hosts (or CIDR ranges) only`);
    }
  }
  for (const k of ["notBefore", "notAfter"] as const) {
    if (scope[k] !== undefined && (typeof scope[k] !== "string" || Number.isNaN(Date.parse(scope[k])))) {
      throw new Error(`${path}: ${k} must be an ISO date string`);
    }
  }
  return scope;
}

/** Active testing only inside the rules-of-engagement window; triage of collected data is not limited. */
export function assertScanWindow(scope: Scope, now: Date = new Date()): void {
  if (scope.notBefore && now < new Date(scope.notBefore)) {
    throw new Error(`testing window opens ${scope.notBefore} — refusing to scan`);
  }
  if (scope.notAfter && now > new Date(scope.notAfter)) {
    throw new Error(`testing window closed ${scope.notAfter} — refusing to scan`);
  }
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
  // Exclusions travel as "!entry" so every isInScope caller enforces them.
  for (const e of scope.exclude ?? []) if (e.trim()) out.add("!" + e.trim().replace(/^!/, ""));
  out.delete("");
  if (![...out].some((e) => !e.startsWith("!"))) {
    throw new Error(
      "scope produced no matchable entries — expected string targets or objects with host/ip/url/domain/name/cidr/target keys",
    );
  }
  for (const entry of out) validateScopeEntry(entry);
  return [...out];
}

/** Validate CIDR notation when slash prefix is present on an IP target. */
export function validateScopeEntry(entry: string): void {
  const trimmed = unbracket(entry.trim().replace(/^!/, ""));
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

/** Host with scheme, path, port and brackets stripped; lowercased. */
export function hostOf(value: string): string {
  const v = value.trim();
  try {
    const u = new URL(v);
    if (u.hostname) return unbracket(u.hostname).toLowerCase();
  } catch {
    /* not a URL — fall through */
  }
  const raw = v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split("/")[0]!;
  const bracketed = raw.match(/^\[([^\]]*)\]/); // "[v6]:port" — the port is outside the brackets
  return (bracketed ? bracketed[1]! : stripPort(raw)).toLowerCase();
}

/** Exclusions ("!entry") win over inclusions. */
export function isInScope(target: string, entries: string[]): boolean {
  const host = hostOf(target);
  const lowerTarget = target.trim().toLowerCase();
  const hit = (e: string) => matchesEntry(host, lowerTarget, e);
  if (entries.some((e) => e.startsWith("!") && hit(e.slice(1)))) return false;
  return entries.some((e) => !e.startsWith("!") && hit(e));
}

function matchesEntry(host: string, lowerTarget: string, entry: string): boolean {
  const cidr = cidrOf(entry.trim());
  if (cidr) {
    const ip = ipv4num(host);
    return ip !== null && inCidr(ip, cidr);
  }
  const v6cidr = ipv6CidrOf(entry.trim());
  if (v6cidr) {
    const ip6 = ipv6num(host);
    return ip6 !== null && inIpv6Cidr(ip6, v6cidr);
  }
  const pattern = hostOf(entry);
  if (!pattern) return false;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return host === base || host.endsWith("." + base);
  }
  // A bare host authorizes only itself; subdomains need an explicit *.wildcard.
  return host === pattern || lowerTarget === entry.trim().toLowerCase(); // second: non-host targets (exact strings)
}

export function filterInScope(findings: Finding[], entries: string[]): { inScope: Finding[]; outOfScope: Finding[] } {
  const inScope: Finding[] = [];
  const outOfScope: Finding[] = [];
  for (const f of findings) (isInScope(f.target, entries) ? inScope : outOfScope).push(f);
  return { inScope, outOfScope };
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