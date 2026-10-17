import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function cli(args: string[], env: NodeJS.ProcessEnv = {}): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("scan cli: `skills` lists the reviewed built-ins", () => {
  const r = cli(["skills"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /http-baseline/);
  assert.match(r.stdout, /service-discovery/);
  assert.match(r.stdout, /passive/);
  assert.match(r.stdout, /active/);
});

test("scan cli: dry run prints the exact argv for every step and writes nothing", () => {
  const out = join(tmpdir(), `vapt-dry-${Date.now()}`);
  const r = cli([
    "scan",
    "--skill",
    "http-baseline",
    "--target",
    "https://app.example.com",
    "-s",
    "examples/scope.json",
    "-o",
    out,
    "--dry-run",
  ]);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /\[1\/2\] httpx -json -silent -u https:\/\/app\.example\.com/);
  assert.match(r.stderr, /\[2\/2\] nuclei -jsonl -silent .* -u https:\/\/app\.example\.com/);
  assert.ok(!existsSync(out), "dry run must not create the findings directory");
});

test("scan cli: refuses out-of-scope targets and non-applicable skills", () => {
  const outOfScope = cli(["scan", "--skill", "http-baseline", "--target", "evil.example.net", "-s", "examples/scope.json", "--dry-run"]);
  assert.equal(outOfScope.status, 1);
  assert.match(outOfScope.stderr, /outside the confirmed scope/);

  const wrongKind = cli(["scan", "--skill", "http-baseline", "--target", "10.10.0.55", "-s", "examples/scope.json", "--dry-run"]);
  assert.equal(wrongKind.status, 1);
  assert.match(wrongKind.stderr, /does not apply/);
});

test("scan cli: non-interactive runs require --yes", () => {
  const r = cli(["scan", "--skill", "service-discovery", "--target", "app.example.com", "-s", "examples/scope.json"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /confirmation needs a TTY/);
});

test("scan cli: executes a skill through PATH, writes findings and the ledger", () => {
  const dir = join(tmpdir(), `vapt-scan-${Date.now()}`);
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  const fakeNmap = join(bin, "nmap");
  writeFileSync(fakeNmap, '#!/bin/sh\nprintf "Host: app.example.com ()\\tPorts: 443/open/tcp//https//nginx 1.25/\\n"\n', { mode: 0o755 });

  const out = join(dir, "findings");
  const ledger = join(dir, "report", "scan-ledger.jsonl");
  const r = cli(
    [
      "scan",
      "--skill",
      "service-discovery",
      "--target",
      "app.example.com",
      "-s",
      "examples/scope.json",
      "-o",
      out,
      "--ledger",
      ledger,
      "--yes",
    ],
    { PATH: `${bin}:${process.env.PATH}` },
  );

  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /saved: .*service-discovery-.*\.json/);
  const saved = r.stderr.match(/saved: (\S+)/)?.[1];
  assert.ok(saved && existsSync(saved), "findings file must exist");
  const records = JSON.parse(readFileSync(saved!, "utf8"));
  assert.equal(records.length, 1);
  assert.equal(records[0].target, "app.example.com:443");
  assert.equal(records[0].tool, "nmap");

  const entries = readFileSync(ledger, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(entries.length, 1);
  assert.equal(entries[0].tool, "nmap");
  assert.equal(entries[0].exitCode, 0);
  assert.equal(entries[0].step, 1);
});
