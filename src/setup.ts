import { createInterface } from "node:readline/promises";
import { type VaptConfig, loadConfig, saveConfig } from "./config.js";
import { box, cyan, dim, yellow } from "./ui.js";

interface Provider {
  name: string;
  baseUrl?: string; // undefined = ask for a custom URL
  models: string[];
}

const PROVIDERS: Provider[] = [
  {
    name: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    models: ["anthropic/claude-sonnet-4.5", "openai/gpt-4o-mini", "meta-llama/llama-3.3-70b-instruct"],
  },
  { name: "Groq", baseUrl: "https://api.groq.com/openai/v1", models: ["llama-3.3-70b-versatile"] },
  { name: "OpenAI", baseUrl: "https://api.openai.com/v1", models: ["gpt-4o-mini", "gpt-4o"] },
  { name: "Meta Model API", baseUrl: "https://api.meta.ai/v1", models: ["muse-spark-1.3"] },
  { name: "Anthropic", baseUrl: "https://api.anthropic.com/v1", models: ["claude-sonnet-4-6", "claude-opus-5-5"] },
  { name: "Custom (OpenAI-compatible)", models: [] },
];

const MAX_MODEL_CHOICES = 25;

async function fetchModels(baseUrl: string, apiKey: string | undefined): Promise<string[]> {
  try {
    const res = await fetch(`${baseUrl.replace(/\/+$/, "")}/models`, {
      headers: apiKey ? { authorization: `Bearer ${apiKey}` } : {},
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as any;
    const list: unknown[] = data?.data ?? data?.models ?? [];
    return list.map((m: any) => m?.id ?? m?.name).filter((v): v is string => typeof v === "string" && v.length > 0);
  } catch {
    return [];
  }
}

/** Question with the typed input masked (documented readline pattern; falls back to plain). */
function maskedQuestion(rl: ReturnType<typeof createInterface>, prompt: string): Promise<string> {
  const iface = rl as unknown as { _writeToOutput?: (s: string) => void; output: NodeJS.WritableStream };
  const original = iface._writeToOutput;
  if (typeof original !== "function") return rl.question(prompt);
  iface._writeToOutput = (s: string) => {
    if (/^[\r\n]+$/.test(s)) iface.output.write(s);
    else iface.output.write("*".repeat(s.length));
  };
  return rl.question(prompt).finally(() => {
    iface._writeToOutput = original;
  });
}

/** First-run wizard: provider → API key → model, saved to the config file. */
export async function runSetup(): Promise<VaptConfig> {
  if (!process.stdin.isTTY) {
    throw new Error("setup needs a TTY — for headless use set VAPT_LLM_BASE_URL / VAPT_LLM_MODEL / VAPT_LLM_API_KEY");
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    process.stderr.write(
      "\n" + box(PROVIDERS.map((p, i) => `${dim(`${i + 1}.`)} ${p.name}`), "setup — connect a model") + "\n\n",
    );

    const pick = (await rl.question(`${cyan("provider")} ${dim(`[1-${PROVIDERS.length}]`)} (1): `)).trim() || "1";
    const provider = PROVIDERS[Number(pick) - 1];
    if (!provider) throw new Error(`invalid provider choice: ${pick}`);

    let baseUrl = provider.baseUrl ?? "";
    if (!baseUrl) {
      baseUrl = (await rl.question(`${cyan("base url")} ${dim("(OpenAI-compatible, e.g. http://localhost:11434/v1)")}: `)).trim();
    }
    if (!baseUrl) throw new Error("base url is required");

    const apiKey = (await maskedQuestion(rl, `${cyan("api key")} ${dim("(hidden as you type)")}: `)).trim();
    if (!apiKey && !/localhost|127\.0\.0\.1/.test(baseUrl)) {
      process.stderr.write(yellow("warn: no api key — fine for local endpoints, most providers will reject requests") + "\n");
    }

    process.stderr.write(dim("checking available models…") + "\n");
    const live = await fetchModels(baseUrl, apiKey || undefined);
    const models = (live.length ? live : provider.models).slice(0, MAX_MODEL_CHOICES);

    let model: string;
    if (models.length) {
      for (const [i, m] of models.entries()) process.stderr.write(`  ${dim(`${i + 1}.`)} ${m}\n`);
      const raw = (await rl.question(`${cyan("model")} ${dim(`[1-${models.length}]`)} (default: ${models[0]}): `)).trim();
      model = !raw ? models[0]! : /^\d+$/.test(raw) ? (models[Number(raw) - 1] ?? models[0]!) : raw;
    } else {
      model = (await rl.question(`${cyan("model")} ${dim("(e.g. gpt-4o-mini, llama3.1, muse-spark-1.3)")}: `)).trim();
    }
    if (!model) throw new Error("model is required");

    const cfg: VaptConfig = { provider: provider.name, baseUrl, model, ...(apiKey ? { apiKey } : {}) };
    const path = saveConfig(cfg);
    process.stderr.write(
      "\n" +
        box(
          [
            `provider   ${provider.name}`,
            `model      ${model}`,
            `base url   ${baseUrl}`,
            `saved to   ${path}`,
            "",
            dim("api key stored owner-only (0600); VAPT_LLM_* env vars override this config"),
          ],
          "setup complete",
        ) +
        "\n\n",
    );
    return cfg;
  } finally {
    rl.close();
  }
}

/** Run onboarding when nothing is configured yet (interactive callers only). */
export async function ensureConfigured(): Promise<void> {
  if (process.env.VAPT_LLM_MODEL || loadConfig()) return;
  if (!process.stdin.isTTY) {
    throw new Error("no model configured — run `vapt setup`, or set VAPT_LLM_MODEL / VAPT_LLM_BASE_URL / VAPT_LLM_API_KEY");
  }
  await runSetup();
}