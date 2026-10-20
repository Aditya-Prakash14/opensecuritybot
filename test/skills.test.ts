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
    "http-baseline",
    "service-discovery",
    "takeover-check",
    "web-fingerprint",
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

test("normalizers: unknown name throws", () => {
  assert.throws(() => normalizeOutput("bogus", "", "fallback"), /unknown normalizer: bogus/);
});
