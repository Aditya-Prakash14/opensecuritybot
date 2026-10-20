import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { configDir, loadConfig, saveConfig } from "./config.js";

export interface WorkspaceInfo {
  name: string;
  path: string;
  isActive: boolean;
  engagement?: string;
  targetCount: number;
}

export function workspacesRoot(): string {
  return process.env.VAPT_WORKSPACES_ROOT ?? join(configDir(), "workspaces");
}

export function getActiveWorkspace(): string | null {
  const cfg = loadConfig();
  return cfg?.activeWorkspace ?? null;
}

function assertWorkspaceName(name: string): void {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    throw new Error(`invalid workspace name "${name}" — use letters, digits, dot, underscore or dash`);
  }
}

export function setActiveWorkspace(name: string): void {
  assertWorkspaceName(name);
  const root = workspacesRoot();
  const dir = join(root, name);
  if (!existsSync(dir)) {
    throw new Error(`workspace "${name}" does not exist at ${dir}`);
  }
  const cfg = loadConfig();
  if (!cfg) {
    throw new Error("vapt is not configured yet — run `vapt setup` first");
  }
  cfg.activeWorkspace = name;
  saveConfig(cfg);
}

export function createWorkspace(
  name: string,
  options?: { engagement?: string; targets?: string[] },
): string {
  assertWorkspaceName(name);
  const root = workspacesRoot();
  const dir = join(root, name);
  if (existsSync(dir)) {
    throw new Error(`workspace "${name}" already exists at ${dir}`);
  }

  mkdirSync(join(dir, "cve-cache"), { recursive: true });
  mkdirSync(join(dir, "report"), { recursive: true });

  const scopePath = join(dir, "scope.json");
  const scopeData = {
    engagement: options?.engagement ?? name,
    targets: options?.targets ?? ["example.com", "*.api.example.com", "10.10.0.0/24"],
  };
  writeFileSync(scopePath, JSON.stringify(scopeData, null, 2) + "\n", "utf8");

  // If no workspace is active yet, automatically activate this one
  const cfg = loadConfig();
  if (cfg && !cfg.activeWorkspace) {
    cfg.activeWorkspace = name;
    saveConfig(cfg);
  }

  return dir;
}

export function listWorkspaces(): WorkspaceInfo[] {
  const root = workspacesRoot();
  if (!existsSync(root)) return [];

  const active = getActiveWorkspace();
  const entries = readdirSync(root, { withFileTypes: true });
  const results: WorkspaceInfo[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const dir = join(root, entry.name);
    const scopePath = join(dir, "scope.json");
    let engagement: string | undefined;
    let targetCount = 0;
    if (existsSync(scopePath)) {
      try {
        const parsed = JSON.parse(readFileSync(scopePath, "utf8"));
        engagement = parsed.engagement;
        if (Array.isArray(parsed.targets)) targetCount = parsed.targets.length;
      } catch {
        /* ignore invalid scope in list */
      }
    }
    results.push({ name: entry.name, path: dir, isActive: entry.name === active, engagement, targetCount });
  }

  return results.sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * If a relative path exists in the current working directory, use it.
 * Otherwise, if an active workspace is set and the path exists inside it, resolve to the workspace.
 */
export function resolveWorkspacePath(relPath: string): string {
  if (existsSync(relPath)) return relPath;
  const active = getActiveWorkspace();
  if (active) {
    const candidate = join(workspacesRoot(), active, relPath);
    if (existsSync(candidate)) return candidate;
  }
  return relPath;
}
