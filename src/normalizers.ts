export const NORMALIZERS = ["httpx-jsonl", "nuclei-jsonl", "nmap-grepable"] as const;
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
