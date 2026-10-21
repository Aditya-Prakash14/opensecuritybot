import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import test from "node:test";
import { loadFindings } from "../src/findings.js";
import { NORMALIZERS, normalizeOutput } from "../src/normalizers.js";
import {
  getSkill,
  loadSkills,
  renderArgs,
  skillApplies,
  skillsDir,
  targetKind,
  TOOL_ALLOWLIST,
} from "../src/skills.js";

const VALID_SKILL = {
  name: "probe",
  description: "test skill",
  appliesTo: ["url"],
  risk: "passive",
  steps: [{ tool: "httpx", args: ["-json", "-u", "{{target}}"] }],
  parsers: ["httpx-jsonl"],
};

function writeSkillDir(files: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "vapt-skills-"));
  for (const [file, body] of Object.entries(files)) {
    writeFileSync(join(dir, file), typeof body === "string" ? body : JSON.stringify(body));
  }
  return dir;
}

test("skills: real skills/ dir loads every skill, sorted by file name", () => {
  const skills = loadSkills("skills");
  assert.deepEqual(skills.map((s) => s.name), [
    "cve-scan",
    "exposed-panels",
    "content-discovery",
    "http-baseline",
    "port-sweep",
    "service-discovery",
    "subdomain-discovery",
    "takeover-check",
    "web-fingerprint",
    "wpscan",
  ]);
  for (const skill of skills) {
    assert.equal(skill.steps.length, skill.parsers.length);
    for (const step of skill.steps) assert.ok((TOOL_ALLOWLIST as readonly string[]).includes(step.tool));
    for (const parser of skill.parsers) assert.ok((NORMALIZERS as readonly string[]).includes(parser));
  }
});

test("skills: new reviewed skills load, validate and render argv with the target", () => {
  const expected: Record<string, { risk: string; parsers: string[]; tools: string[]; renders: string }> = {
    "cve-scan": { risk: "active", parsers: ["nuclei-jsonl"], tools: ["nuclei"], renders: "https://app.example.com" },
    "exposed-panels": { risk: "passive", parsers: ["nuclei-jsonl"], tools: ["nuclei"], renders: "https://app.example.com" },
    "takeover-check": { risk: "passive", parsers: ["nuclei-jsonl"], tools: ["nuclei"], renders: "https://app.example.com" },
    "web-fingerprint": { risk: "passive", parsers: ["httpx-jsonl", "nuclei-jsonl"], tools: ["httpx", "nuclei"], renders: "https://app.example.com" },
    "port-sweep": { risk: "active", parsers: ["masscan-json"], tools: ["masscan"], renders: "10.10.0.5" },
    "subdomain-discovery": { risk: "passive", parsers: ["subfinder-jsonl"], tools: ["subfinder"], renders: "app.example.com" },
    "wpscan": { risk: "active", parsers: ["wpscan-json"], tools: ["wpscan"], renders: "https://app.example.com" },
  };
  for (const [name, want] of Object.entries(expected)) {
    const skill = getSkill(name, "skills");
    assert.equal(skill.risk, want.risk);
    assert.deepEqual(skill.parsers, want.parsers);
    assert.equal(skill.steps.length, skill.parsers.length, `${name}: parsers match steps`);
    assert.deepEqual(skill.steps.map((s) => s.tool), want.tools);
    // every step renders {{target}} into the given target and leaves no placeholder behind
    for (const step of skill.steps) {
      const argv = renderArgs(step.args, want.renders);
      assert.ok(argv.includes(want.renders), `${name}: argv carries the target`);
      assert.ok(!argv.some((a) => a.includes("{{")), `${name}: no unrendered placeholder`);
    }
    // nuclei steps carry an explicit timeout (broad tags run for minutes)
    for (const step of skill.steps) {
      if (step.tool === "nuclei") assert.ok((step.timeoutMs ?? 0) > 0, `${name}: nuclei step has a timeout`);
    }
  }
});

test("skills: valid temp skill loads, non-json files ignored, VAPT_SKILLS_DIR wins", () => {
  const dir = writeSkillDir({ "probe.json": VALID_SKILL, "notes.txt": "ignored" });
  const [skill] = loadSkills(dir);
  assert.equal(skill!.name, "probe");
  assert.deepEqual(skill!.steps, [{ tool: "httpx", args: ["-json", "-u", "{{target}}"] }]);
  assert.equal(skill!.risk, "passive");

  const previous = process.env.VAPT_SKILLS_DIR;
  process.env.VAPT_SKILLS_DIR = dir;
  try {
    assert.equal(skillsDir(), dir);
    assert.equal(loadSkills()[0]!.name, "probe");
  } finally {
    if (previous === undefined) delete process.env.VAPT_SKILLS_DIR;
    else process.env.VAPT_SKILLS_DIR = previous;
  }
});

test("skills: default dir is package-relative, not cwd-relative", () => {
  // Regression: a global install must find the bundled skills from any working directory.
  assert.ok(isAbsolute(skillsDir()), `expected an absolute skills dir, got ${skillsDir()}`);
  assert.ok(existsSync(join(skillsDir(), "http-baseline.json")));
});

test("skills: invalid skill files throw with file name and reason", () => {
  const cases: Array<[string, Record<string, unknown>, RegExp]> = [
    ["unknown tool", { ...VALID_SKILL, steps: [{ tool: "curl", args: ["{{target}}"] }] }, /bad\.json: steps\[0\]\.tool "curl" is not allowed/],
    ["bad placeholder", { ...VALID_SKILL, steps: [{ tool: "httpx", args: ["-u", "{{other}}"] }] }, /bad\.json: .*unsupported placeholder/],
    [
      "parser count",
      { ...VALID_SKILL, steps: [{ tool: "httpx", args: [] }, { tool: "nuclei", args: [] }] },
      /bad\.json: parsers length 1 does not match steps length 2/,
    ],
  ];
  for (const [label, body, expected] of cases) {
    assert.throws(() => loadSkills(writeSkillDir({ "bad.json": body })), expected, label);
  }
  assert.throws(() => loadSkills(join(tmpdir(), "vapt-skills-missing-dir")), /not found or unreadable/, "missing dir");
});

test("skills: getSkill resolves exact names and lists available ones", () => {
  assert.equal(getSkill("service-discovery", "skills").steps[0]!.tool, "nmap");
  assert.throws(
    () => getSkill("missing", "skills"),
    /unknown skill "missing".*http-baseline.*service-discovery/,
  );
});

test("skills: targetKind and skillApplies", () => {
  assert.equal(targetKind("https://example.com/a"), "url");
  assert.equal(targetKind("HTTP://example.com"), "url");
  assert.equal(targetKind("example.com"), "host");
  assert.equal(targetKind("10.0.0.5"), "ip");
  assert.equal(targetKind("2001:db8::1"), "ip");

  const http = getSkill("http-baseline", "skills");
  const discovery = getSkill("service-discovery", "skills");
  assert.equal(skillApplies(http, "https://example.com"), true);
  assert.equal(skillApplies(http, "example.com"), true);
  assert.equal(skillApplies(http, "10.0.0.5"), false);
  assert.equal(skillApplies(discovery, "10.0.0.5"), true);
  assert.equal(skillApplies(discovery, "[2001:db8::1]"), true);
  assert.equal(skillApplies(discovery, "https://example.com"), false);
});

test("skills: renderArgs replaces every {{target}} in a new array", () => {
  const args = ["-u", "{{target}}", "-silent", "https://{{target}}/x"];
  const rendered = renderArgs(args, "10.0.0.5");
  assert.deepEqual(rendered, ["-u", "10.0.0.5", "-silent", "https://10.0.0.5/x"]);
  assert.notEqual(rendered, args);
  assert.deepEqual(args, ["-u", "{{target}}", "-silent", "https://{{target}}/x"]);
  assert.deepEqual(renderArgs(["-silent"], "x"), ["-silent"]);
});

test("normalizers: httpx-jsonl maps fields and skips malformed lines", () => {
  const output = [
    JSON.stringify({ url: "https://a.example.com", status_code: 200, title: "Home", tech: ["nginx"], webserver: "nginx" }),
    "not-json",
    JSON.stringify({ input: "https://b.example.com", status_code: 404, webserver: "gunicorn" }),
  ].join("\n");
  const recs = normalizeOutput("httpx-jsonl", output, "fallback");
  assert.equal(recs.length, 2);
  assert.equal(recs[0]!.target, "https://a.example.com");
  assert.equal(recs[0]!.title, "HTTP 200 Home");
  assert.equal(recs[0]!.severity, "info");
  assert.equal(recs[0]!.tool, "httpx");
  assert.equal(recs[0]!.status_code, 200);
  assert.deepEqual(recs[0]!.tech, ["nginx"]);
  assert.equal(recs[0]!.webserver, "nginx");
  assert.equal((recs[0]!.raw as Record<string, unknown>).url, "https://a.example.com");
  assert.equal(recs[1]!.target, "https://b.example.com");
  assert.equal(recs[1]!.title, "HTTP 404 gunicorn");
  assert.deepEqual(normalizeOutput("httpx-jsonl", "", "fallback"), []);
});

test("normalizers: nuclei-jsonl maps info.name/severity/template-id", () => {
  const output = [
    JSON.stringify({
      "template-id": "exposed-panel",
      info: { name: "Exposed panel", severity: "medium", description: "Admin panel exposed" },
      "matched-at": "https://a.example.com/admin",
    }),
    JSON.stringify({ "template-id": "bare", severity: "low" }),
  ].join("\n");
  const recs = normalizeOutput("nuclei-jsonl", output, "fallback");
  assert.equal(recs.length, 2);
  assert.equal(recs[0]!.id, "exposed-panel");
  assert.equal(recs[0]!.target, "https://a.example.com/admin");
  assert.equal(recs[0]!.title, "Exposed panel");
  assert.equal(recs[0]!.severity, "medium");
  assert.equal(recs[0]!.description, "Admin panel exposed");
  assert.equal(recs[0]!.tool, "nuclei");
  assert.equal((recs[0]!.raw as Record<string, unknown>)["template-id"], "exposed-panel");
  assert.equal(recs[1]!.target, "fallback");
  assert.equal(recs[1]!.title, "bare");
  assert.equal(recs[1]!.severity, "low");
});

test("normalizers: nmap-grepable keeps only open ports", () => {
  const output = [
    "# Nmap 7.94 scan initiated",
    "Host: 10.0.0.5 (box.local)\tPorts: 22/open/tcp//ssh//OpenSSH 8.2p1/, 443/open/tcp//https//nginx/, 3306/closed/tcp//mysql///\tIgnored State: closed (1)",
    "Host: 10.0.0.6 ()\tIgnored State: closed (10)",
  ].join("\n");
  const recs = normalizeOutput("nmap-grepable", output, "fallback");
  assert.equal(recs.length, 2);
  assert.equal(recs[0]!.target, "10.0.0.5:22");
  assert.equal(recs[0]!.title, "tcp 22 ssh OpenSSH 8.2p1");
  assert.equal(recs[0]!.severity, "info");
  assert.equal(recs[0]!.tool, "nmap");
  assert.equal(recs[0]!.port, 22);
  assert.equal(recs[0]!.service, "ssh");
  assert.equal(recs[0]!.version, "OpenSSH 8.2p1");
  assert.equal(recs[1]!.target, "10.0.0.5:443");
  assert.equal(recs[1]!.title, "tcp 443 https nginx");
  assert.deepEqual(normalizeOutput("nmap-grepable", "", "fallback"), []);
});

test("normalizers: output shape is understood by loadFindings", () => {
  const record = normalizeOutput(
    "nuclei-jsonl",
    JSON.stringify({ "template-id": "t1", info: { name: "n", severity: "high" }, "matched-at": "https://a.example.com" }),
    "fallback",
  );
  const dir = writeSkillDir({ "normalized.json": record });
  const { findings } = loadFindings(join(dir, "normalized.json"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.id, "t1");
  assert.equal(findings[0]!.target, "https://a.example.com");
  assert.equal(findings[0]!.severity, "high");
  assert.equal(findings[0]!.tool, "nuclei");
});

test("normalizers: masscan-json maps open ports and tolerates the finished record", () => {
  const output = [
    "[",
    '{ "ip": "10.0.0.5", "timestamp": "1700000000", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }',
    ",",
    '{ "ip": "10.0.0.5", "timestamp": "1700000001", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }',
    ",",
    '{"finished": 1}',
    "]",
  ].join("\n");
  const recs = normalizeOutput("masscan-json", output, "fallback");
  assert.equal(recs.length, 2);
  assert.equal(recs[0]!.target, "10.0.0.5:22");
  assert.equal(recs[0]!.title, "tcp 22 open");
  assert.equal(recs[0]!.severity, "info");
  assert.equal(recs[0]!.tool, "masscan");
  assert.equal(recs[0]!.port, 22);
  assert.equal((recs[0]!.raw as Record<string, unknown>).reason, "syn-ack");
  assert.equal(recs[1]!.target, "10.0.0.5:443");
  assert.deepEqual(normalizeOutput("masscan-json", "", "fallback"), []);
});

test("normalizers: subfinder-jsonl maps one finding per discovered subdomain", () => {
  const output = [
    JSON.stringify({ host: "www.hackerone.com", input: "hackerone.com", source: "crtsh" }),
    JSON.stringify({ host: "api.hackerone.com", input: "hackerone.com", source: "dnsdumpster" }),
    "not-json",
    JSON.stringify({ input: "hackerone.com", source: "bufferover" }),
  ].join("\n");
  const recs = normalizeOutput("subfinder-jsonl", output, "hackerone.com");
  assert.equal(recs.length, 3);
  assert.equal(recs[0]!.target, "www.hackerone.com");
  assert.equal(recs[0]!.title, "Subdomain: www.hackerone.com");
  assert.equal(recs[0]!.tool, "subfinder");
  assert.equal(recs[2]!.target, "hackerone.com"); // no host -> fallback
  assert.deepEqual(normalizeOutput("subfinder-jsonl", "", "hackerone.com"), []);
});

test("normalizers: wpscan-json maps version, plugins, themes, users and interesting findings", () => {
  const output = JSON.stringify({
    target_url: "https://blog.example.com/",
    interesting_findings: [{ to_s: "Headers (X-Powered-By: PHP)", type: "headers" }],
    version: { number: "5.8.1", status: "insecure", vulnerabilities: [{ title: "WP 5.8.1 XSS" }] },
    main_theme: { slug: "twentytwentyone", version: { number: "1.3" }, outdated: true, vulnerabilities: [] },
    plugins: {
      "contact-form-7": { version: { number: "5.4" }, outdated: false, vulnerabilities: [{ title: "CF7 upload" }, { title: "CF7 XSS" }] },
      akismet: { version: { number: "4.1.9" }, outdated: true, vulnerabilities: [] },
    },
    users: { admin: { id: 1 } },
  });
  const recs = normalizeOutput("wpscan-json", output, "fallback");
  const byTitle = (t: string) => recs.find((r) => String(r.title).startsWith(t));
  for (const r of recs) assert.equal(r.target, "https://blog.example.com/");
  assert.equal(byTitle("Headers")!.severity, "info");
  assert.equal(byTitle("WordPress 5.8.1")!.severity, "high");
  assert.equal(byTitle("plugin contact-form-7")!.severity, "high");
  assert.ok(String(byTitle("plugin contact-form-7")!.title).includes("2 known vulnerabilities"));
  assert.equal(byTitle("plugin akismet")!.severity, "medium");
  assert.equal(byTitle("theme twentytwentyone")!.severity, "medium");
  assert.equal(byTitle("user admin")!.severity, "info");
  assert.deepEqual(normalizeOutput("wpscan-json", "not json", "fallback"), []);
  assert.deepEqual(normalizeOutput("wpscan-json", "[1,2]", "fallback"), []);
});

test("normalizers: ffuf-json maps discovered paths and skips non-result lines", () => {
  const output = [
    JSON.stringify({ input: { FUZZ: "YWRtaW4=" }, status: 200, length: 1256, url: "https://app.example.com/admin", host: "app.example.com" }),
    JSON.stringify({ input: { FUZZ: "cm9ib3RzLnR4dA==" }, status: 301, redirectlocation: "/robots/", url: "https://app.example.com/robots.txt", host: "app.example.com" }),
    "not-json",
    JSON.stringify({ position: 3, status: 200 }),
  ].join("\n");
  const recs = normalizeOutput("ffuf-json", output, "fallback");
  assert.equal(recs.length, 2);
  assert.equal(recs[0]!.target, "https://app.example.com/admin");
  assert.equal(recs[0]!.title, "Discovered path: https://app.example.com/admin (200)");
  assert.equal(recs[0]!.tool, "ffuf");
  assert.equal(recs[0]!.status_code, 200);
  assert.equal(recs[1]!.status_code, 301);
  assert.deepEqual(normalizeOutput("ffuf-json", "", "fallback"), []);
});

test("normalizers: unknown name throws", () => {
  assert.throws(() => normalizeOutput("bogus", "", "fallback"), /unknown normalizer: bogus/);
});
