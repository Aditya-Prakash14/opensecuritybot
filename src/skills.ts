import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { NORMALIZERS } from "./normalizers.js";

export const TOOL_ALLOWLIST = ["nmap", "nuclei", "httpx"] as const;

export type TargetKind = "url" | "host" | "ip";

export interface SkillStep {
  tool: string;
  args: string[];
  timeoutMs?: number;
}

export interface Skill {
  name: string;
  description: string;
  appliesTo: TargetKind[];
  risk: "passive" | "active";
  steps: SkillStep[];
  parsers: string[];
}

const PLACEHOLDER = /\{\{[^}]+\}\}/g;

// Built-in skills ship at the package root (dist/skills.js -> ../skills), so a global
// install resolves them from any working directory.
const BUILTIN_SKILLS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "skills");

/** VAPT_SKILLS_DIR overrides the skills directory; otherwise the bundled skills/ is used. */
export function skillsDir(): string {
  return process.env.VAPT_SKILLS_DIR ?? BUILTIN_SKILLS_DIR;
}

export function loadSkills(dir: string = skillsDir()): Skill[] {
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  } catch (e) {
    throw new Error(`skills directory not found or unreadable at ${dir} (${(e as Error).message})`);
  }
  return files.map((file) => validateSkill(readSkillJson(join(dir, file), file), file));
}

function readSkillJson(path: string, file: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`${file}: not readable as JSON (${(e as Error).message})`);
  }
}

function validateSkill(raw: unknown, file: string): Skill {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${file}: expected a JSON object`);
  const s = raw as Record<string, unknown>;

  const name = s.name;
  const description = s.description;
  if (typeof name !== "string" || !name.trim()) throw new Error(`${file}: name must be a non-empty string`);
  if (typeof description !== "string" || !description.trim()) throw new Error(`${file}: description must be a non-empty string`);

  const rawApplies = s.appliesTo;
  if (!Array.isArray(rawApplies) || rawApplies.length === 0) throw new Error(`${file}: appliesTo must be a non-empty array`);
  const appliesTo: TargetKind[] = [];
  for (const kind of rawApplies as unknown[]) {
    if (kind !== "url" && kind !== "host" && kind !== "ip") {
      throw new Error(`${file}: appliesTo has unknown target kind "${String(kind)}" (allowed: url, host, ip)`);
    }
    appliesTo.push(kind);
  }

  const risk = s.risk;
  if (risk !== "passive" && risk !== "active") throw new Error(`${file}: risk must be "passive" or "active"`);

  const rawSteps = s.steps;
  if (!Array.isArray(rawSteps) || rawSteps.length === 0) throw new Error(`${file}: steps must be a non-empty array`);
  const steps: SkillStep[] = (rawSteps as unknown[]).map((step, i) => {
    if (!step || typeof step !== "object" || Array.isArray(step)) throw new Error(`${file}: steps[${i}] must be an object`);
    const st = step as Record<string, unknown>;
    if (typeof st.tool !== "string" || !(TOOL_ALLOWLIST as readonly string[]).includes(st.tool)) {
      throw new Error(`${file}: steps[${i}].tool "${String(st.tool)}" is not allowed (allowed: ${TOOL_ALLOWLIST.join(", ")})`);
    }
    const rawArgs = st.args;
    if (!Array.isArray(rawArgs)) throw new Error(`${file}: steps[${i}].args must be an array of strings`);
    const args: string[] = [];
    for (const rawArg of rawArgs as unknown[]) {
      if (typeof rawArg !== "string") throw new Error(`${file}: steps[${i}].args must be strings`);
      const bad = rawArg.match(PLACEHOLDER)?.find((p) => p !== "{{target}}");
      if (bad) throw new Error(`${file}: steps[${i}].args contains unsupported placeholder "${bad}" (only {{target}} is allowed)`);
      args.push(rawArg);
    }
    const out: SkillStep = { tool: st.tool, args };
    const timeout = st.timeoutMs;
    if (timeout !== undefined) {
      if (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout <= 0) {
        throw new Error(`${file}: steps[${i}].timeoutMs must be a positive number`);
      }
      out.timeoutMs = timeout;
    }
    return out;
  });

  const rawParsers = s.parsers;
  if (!Array.isArray(rawParsers) || rawParsers.length === 0) throw new Error(`${file}: parsers must be a non-empty array`);
  const parsers: string[] = [];
  for (const parser of rawParsers as unknown[]) {
    if (typeof parser !== "string" || !(NORMALIZERS as readonly string[]).includes(parser)) {
      throw new Error(`${file}: unknown parser "${String(parser)}" (allowed: ${NORMALIZERS.join(", ")})`);
    }
    parsers.push(parser);
  }
  if (parsers.length !== steps.length) {
    throw new Error(`${file}: parsers length ${parsers.length} does not match steps length ${steps.length}`);
  }

  return { name, description, appliesTo, risk, steps, parsers };
}

export function getSkill(name: string, dir: string = skillsDir()): Skill {
  const skills = loadSkills(dir);
  const skill = skills.find((s) => s.name === name);
  if (!skill) {
    throw new Error(`unknown skill "${name}" — available: ${skills.map((s) => s.name).join(", ") || "(none)"}`);
  }
  return skill;
}

export function renderArgs(args: string[], target: string): string[] {
  return args.map((a) => a.replaceAll("{{target}}", target));
}

export function targetKind(target: string): TargetKind {
  const t = target.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return "url";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(t) || t.includes(":")) return "ip";
  return "host";
}

export function skillApplies(skill: Skill, target: string): boolean {
  return skill.appliesTo.includes(targetKind(target));
}
