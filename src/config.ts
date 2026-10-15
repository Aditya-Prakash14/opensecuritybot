import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface VaptConfig {
  provider: string;
  baseUrl: string;
  model: string;
  apiKey?: string;
}

export function configDir(): string {
  return process.env.VAPT_CONFIG_DIR ?? join(homedir(), ".config", "vapt");
}

export function configPath(): string {
  return join(configDir(), "config.json");
}

export function loadConfig(): VaptConfig | null {
  try {
    const raw = JSON.parse(readFileSync(configPath(), "utf8")) as VaptConfig;
    if (typeof raw?.baseUrl !== "string" || typeof raw?.model !== "string") return null;
    return raw;
  } catch {
    return null;
  }
}

/** Save owner-only — the file may hold an API key. */
export function saveConfig(cfg: VaptConfig): string {
  mkdirSync(configDir(), { recursive: true, mode: 0o700 });
  const path = configPath();
  writeFileSync(path, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best effort on filesystems without modes */
  }
  return path;
}