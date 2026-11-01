import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { chat } from "../src/llm.js";
import { assertTargetAllowed } from "../src/runner.js";
import { hostOf, isInScope } from "../src/scope-guard.js";

function cli(args: string[], env: NodeJS.ProcessEnv = {}): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function fixtures(dir: string): { bPath: string; cPath: string } {
  const bPath = join(dir, "baseline.json");
  const cPath = join(dir, "current.json");
  writeFileSync(bPath, JSON.stringify([{ id: "F-1", target: "example.com", title: "Bug A", severity: "high" }]));
  writeFileSync(cPath, JSON.stringify([{ id: "F-2", target: "example.com", title: "Bug B", severity: "low" }]));
  return { bPath, cPath };
}

test("diff cli: markdown goes to stdout without -q, summary goes to stderr", () => {
  const { bPath, cPath } = fixtures(mkdtempSync(join(tmpdir(), "vapt-diff-md-")));
  const r = cli(["diff", "-b", bPath, "-c", cPath]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^# /m, "markdown report expected on stdout");
  assert.ok(!r.stdout.includes("Remediation Delta Summary"), "summary must not pollute stdout");
  assert.match(r.stderr, /Remediation Delta Summary/);

  const quiet = cli(["diff", "-b", bPath, "-c", cPath, "-q"]);
  assert.equal(quiet.status, 0);
  assert.match(quiet.stdout, /^# /m);
  assert.ok(!quiet.stderr.includes("Remediation Delta Summary"));
});

test("diff cli: baseline/current/scope resolve through the active workspace", () => {
  const dir = mkdtempSync(join(tmpdir(), "vapt-diff-ws-"));
  const wsRoot = join(dir, "workspaces");
  const ws = join(wsRoot, "acme");
  mkdirSync(ws, { recursive: true });
  fixtures(ws);
  writeFileSync(join(ws, "scope.json"), JSON.stringify({ targets: ["example.com"] }));
  writeFileSync(
    join(dir, "config.json"),
    JSON.stringify({ baseUrl: "https://api.openai.com/v1", model: "stub", activeWorkspace: "acme" }),
  );

  const r = cli(["diff", "-b", "baseline.json", "-c", "current.json", "-s", "scope.json", "--json"], {
    VAPT_CONFIG_DIR: dir,
    VAPT_WORKSPACES_ROOT: wsRoot,
  });
  assert.equal(r.status, 0, r.stderr);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.baselineTotal, 1);
  assert.equal(parsed.currentTotal, 1);
});

test("llm: chat() aborts a response whose body never ends", async (t) => {
  const origFetch = globalThis.fetch;
  const origEnv = { ...process.env };
  t.after(() => {
    globalThis.fetch = origFetch;
    process.env = origEnv;
  });
  process.env.VAPT_LLM_MODEL = "stub";
  process.env.VAPT_LLM_TIMEOUT_MS = "200";
  process.env.VAPT_LLM_RETRY_DELAY_MS = "0";
  // Headers arrive, the body never does; like real fetch, the stream errors when the signal aborts.
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    const signal = init?.signal;
    const body = new ReadableStream({
      start(controller) {
        signal?.addEventListener("abort", () => controller.error(signal.reason));
      },
    });
    return new Response(body, { status: 200 });
  }) as typeof fetch;

  const started = Date.now();
  await assert.rejects(chat([{ role: "user", content: "hi" }]), /timeout/);
  assert.ok(Date.now() - started < 1500, "three 200ms attempts must finish well under 1.5s");
});

test("scope-guard: hostOf is shared by runner and handles bracketed IPv6 with a port", () => {
  assert.equal(hostOf("[fd00:ec2::254]:8080"), "fd00:ec2::254");
  assert.equal(hostOf("METADATA.GOOGLE.INTERNAL:80"), "metadata.google.internal");
  assert.equal(hostOf("http://169.254.169.254/latest/meta-data/"), "169.254.169.254");
  assert.ok(isInScope("[fd00:ec2::254]:8080", ["fd00:ec2::254"]));
  assert.throws(() => assertTargetAllowed("[fd00:ec2::254]:8080", ["fd00:ec2::254"]), /metadata/);
});
