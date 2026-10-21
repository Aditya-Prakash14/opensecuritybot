export const NORMALIZERS = ["httpx-jsonl", "nuclei-jsonl", "nmap-grepable", "masscan-json", "subfinder-jsonl", "wpscan-json", "ffuf-json"] as const;
export type NormalizerName = (typeof NORMALIZERS)[number];

type Obj = Record<string, unknown>;

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/** JSONL lines that fail to parse or are not objects are skipped, never fatal. */
function parseJsonLines(output: string): Obj[] {
  const out: Obj[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) out.push(parsed);
    } catch {
      /* malformed line: skip */
    }
  }
  return out;
}

export function normalizeOutput(name: string, output: string, fallbackTarget: string): Obj[] {
  switch (name) {
    case "httpx-jsonl":
      return httpxJsonl(output, fallbackTarget);
    case "nuclei-jsonl":
      return nucleiJsonl(output, fallbackTarget);
    case "nmap-grepable":
      return nmapGrepable(output, fallbackTarget);
    case "masscan-json":
      return masscanJson(output, fallbackTarget);
    case "subfinder-jsonl":
      return subfinderJsonl(output, fallbackTarget);
    case "wpscan-json":
      return wpscanJson(output, fallbackTarget);
    case "ffuf-json":
      return ffufJson(output, fallbackTarget);
    default:
      throw new Error(`unknown normalizer: ${name}`);
  }
}

function httpxJsonl(output: string, fallbackTarget: string): Obj[] {
  return parseJsonLines(output).map((o) => {
    const status = o.status_code === undefined || o.status_code === null ? "?" : String(o.status_code);
    const tech = Array.isArray(o.tech) ? o.tech.filter((t): t is string => typeof t === "string") : undefined;
    const fingerprint = str(o.title) ?? str(o.webserver) ?? tech?.join(", ");
    const rec: Obj = {
      target: str(o.url) ?? str(o.input) ?? fallbackTarget,
      title: `HTTP ${status}${fingerprint ? ` ${fingerprint}` : ""}`,
      severity: "info",
      tool: "httpx",
      raw: o,
    };
    if (o.status_code !== undefined) rec.status_code = o.status_code;
    if (tech) rec.tech = tech;
    if (o.webserver !== undefined) rec.webserver = o.webserver;
    return rec;
  });
}

function nucleiJsonl(output: string, fallbackTarget: string): Obj[] {
  return parseJsonLines(output).map((o) => {
    const info = o.info && typeof o.info === "object" && !Array.isArray(o.info) ? (o.info as Obj) : {};
    const id = str(o["template-id"]) ?? str(o.templateID) ?? str(o.template) ?? "nuclei";
    const rec: Obj = {
      id,
      target: str(o["matched-at"]) ?? str(o.matched_at) ?? str(o.host) ?? str(o.url) ?? fallbackTarget,
      title: str(info.name) ?? str(o.name) ?? id,
      severity: str(info.severity) ?? str(o.severity) ?? "info",
      tool: "nuclei",
      raw: o,
    };
    const description = str(info.description);
    if (description) rec.description = description;
    return rec;
  });
}

/** nmap -oG: `Host: 10.0.0.5 (name) Ports: 22/open/tcp//ssh//OpenSSH 8.2p1/, ...` */
function nmapGrepable(output: string, fallbackTarget: string): Obj[] {
  const out: Obj[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const portsField = /Ports:\s*([^\t]+)/.exec(trimmed)?.[1];
    if (!portsField) continue;
    const host = /Host:\s*(\S+)/.exec(trimmed)?.[1] ?? fallbackTarget;
    for (const entry of portsField.split(",")) {
      const [port, state, proto, , service, , version] = entry.trim().split("/");
      if (!port || !/^\d+$/.test(port) || state !== "open") continue;
      const base = [proto, port, service].filter(Boolean).join(" ");
      out.push({
        target: `${host}:${port}`,
        title: version ? `${base} ${version}` : base,
        severity: "info",
        tool: "nmap",
        port: Number(port),
        service,
        version,
        raw: { host, port: Number(port), proto, service, version },
      });
    }
  }
  return out;
}

/** masscan -oJ -: `[ {"ip":"1.2.3.4","ports":[{"port":443,"proto":"tcp","status":"open",…}]}, … ]`, maybe with a trailing {"finished":1}; empty output (no open ports) is valid. */
function masscanJson(output: string, fallbackTarget: string): Obj[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(output);
  } catch {
    return []; // no open ports (empty) or malformed: never fatal
  }
  const records = Array.isArray(parsed) ? parsed : [parsed];
  const out: Obj[] = [];
  for (const rec of records) {
    if (!rec || typeof rec !== "object" || Array.isArray(rec)) continue;
    const o = rec as Obj;
    const ip = str(o.ip) ?? fallbackTarget;
    if (!Array.isArray(o.ports)) continue; // skips the {"finished":1} record
    for (const p of o.ports) {
      if (!p || typeof p !== "object" || Array.isArray(p)) continue;
      const pt = p as Obj;
      const port = pt.port;
      if (typeof port !== "number" || !Number.isInteger(port) || pt.status !== "open") continue;
      const proto = str(pt.proto) ?? "tcp";
      out.push({
        target: `${ip}:${port}`,
        title: `${proto} ${port} open`,
        severity: "info",
        tool: "masscan",
        port,
        raw: { ip, port, proto, status: pt.status, reason: pt.reason, ttl: pt.ttl },
      });
    }
  }
  return out;
}

/** subfinder -oJ: one JSON object per line, `{host, input, source}`; one info finding per discovered subdomain. */
function subfinderJsonl(output: string, fallbackTarget: string): Obj[] {
  return parseJsonLines(output).map((o) => {
    const host = str(o.host) ?? fallbackTarget;
    return { target: host, title: `Subdomain: ${host}`, severity: "info", tool: "subfinder", raw: o };
  });
}

/** wpscan --format json emits ONE JSON object. Malformed output yields no findings. */
function wpscanJson(output: string, fallbackTarget: string): Obj[] {
  let data: unknown;
  try {
    data = JSON.parse(output);
  } catch {
    return [];
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) return [];
  const root = data as Obj;
  const target = str(root.target_url) ?? str(root.target_ip) ?? fallbackTarget;
  const out: Obj[] = [];
  const push = (title: string | undefined, severity: string, raw: unknown) => {
    if (title) out.push({ target, title, severity, tool: "wpscan", raw });
  };
  const vulnCount = (o: Obj) => (Array.isArray(o.vulnerabilities) ? o.vulnerabilities.length : 0);
  const plural = (n: number) => `${n} known vulnerabilit${n === 1 ? "y" : "ies"}`;

  if (Array.isArray(root.interesting_findings)) {
    for (const f of root.interesting_findings) {
      if (!f || typeof f !== "object" || Array.isArray(f)) continue;
      const o = f as Obj;
      push(str(o.to_s) ?? str(o.type), "info", o);
    }
  }
  if (root.version && typeof root.version === "object" && !Array.isArray(root.version)) {
    const v = root.version as Obj;
    const vulns = vulnCount(v);
    const status = str(v.status);
    const severity = vulns > 0 || status === "insecure" ? "high" : status === "outdated" ? "medium" : "info";
    const suffix = vulns ? ` — ${plural(vulns)}` : status ? ` (${status})` : "";
    push(`WordPress ${str(v.number) ?? "version"}${suffix}`, severity, v);
  }
  const components: Array<[string, unknown]> = [];
  for (const key of ["plugins", "themes"] as const) {
    const group = root[key];
    if (group && typeof group === "object" && !Array.isArray(group)) {
      for (const [slug, comp] of Object.entries(group as Obj)) components.push([`${key.slice(0, -1)} ${slug}`, comp]);
    }
  }
  if (root.main_theme && typeof root.main_theme === "object" && !Array.isArray(root.main_theme)) {
    const mt = root.main_theme as Obj;
    components.push([`theme ${str(mt.slug) ?? "main"}`, mt]);
  }
  for (const [label, comp] of components) {
    if (!comp || typeof comp !== "object" || Array.isArray(comp)) continue;
    const c = comp as Obj;
    const vulns = vulnCount(c);
    const version = c.version && typeof c.version === "object" && !Array.isArray(c.version) ? str((c.version as Obj).number) : undefined;
    const severity = vulns > 0 ? "high" : c.outdated === true ? "medium" : "info";
    const suffix = vulns ? ` — ${plural(vulns)}` : c.outdated === true ? " (outdated)" : "";
    push(`${label}${version ? ` ${version}` : ""}${suffix}`, severity, c);
  }
  if (root.users && typeof root.users === "object" && !Array.isArray(root.users)) {
    for (const [username, u] of Object.entries(root.users as Obj)) push(`user ${username}`, "info", u);
  }
  return out;
}

/** ffuf -json streams one Result per line to stdout; a piped `-of json` file wraps them in {results:[...]}. */
function ffufJson(output: string, _fallbackTarget: string): Obj[] {
  const results: Obj[] = [];
  for (const o of parseJsonLines(output)) {
    if (Array.isArray(o.results)) {
      for (const r of o.results) if (r && typeof r === "object" && !Array.isArray(r)) results.push(r as Obj);
    } else {
      results.push(o);
    }
  }
  return results.flatMap((o) => {
    const url = str(o.url);
    if (!url) return []; // not a result record (summary/config line) — skip
    const status = o.status === undefined || o.status === null ? "?" : String(o.status);
    const rec: Obj = { target: url, title: `Discovered path: ${url} (${status})`, severity: "info", tool: "ffuf", raw: o };
    if (o.status !== undefined && o.status !== null) rec.status_code = o.status;
    return [rec];
  });
}
