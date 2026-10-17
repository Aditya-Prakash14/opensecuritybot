import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { VERSION } from "../src/version.js";

test("version: VERSION matches package.json (bump both in the same commit)", () => {
  const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { version: string };
  assert.equal(VERSION, pkg.version);
});
