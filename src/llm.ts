import { loadConfig } from "./config.js";

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

const RETRYABLE = new Set([429, 500, 502, 503, 504]);
const DEFAULT_BASE = "https://api.openai.com/v1";
const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_STREAM_TIMEOUT_MS = 300_000;

function llmConfig(): {
  base: string;
  model: string;
  key: string | undefined;
  temperature: number | undefined;
  isAnthropic: boolean;
} {
  const cfg = loadConfig();
  const envProvider = process.env.VAPT_LLM_PROVIDER?.toLowerCase();
  const cfgProvider = cfg?.provider?.toLowerCase();
  const provider = envProvider ?? cfgProvider ?? "";
  const key = process.env.VAPT_LLM_API_KEY ?? cfg?.apiKey;
  const model = process.env.VAPT_LLM_MODEL ?? cfg?.model;
  if (!model) {
    throw new Error("no model configured — run `vapt setup`, or set VAPT_LLM_MODEL (optionally VAPT_LLM_BASE_URL / VAPT_LLM_API_KEY)");
  }

  const isAnthropic =
    provider === "anthropic" ||
    (Boolean(process.env.VAPT_LLM_BASE_URL) && /anthropic\.com/.test(process.env.VAPT_LLM_BASE_URL!)) ||
    (Boolean(key) && key!.startsWith("sk-ant-"));

  let base = process.env.VAPT_LLM_BASE_URL;
  if (!base) {
    if (isAnthropic && cfgProvider !== "anthropic") {
      base = "https://api.anthropic.com/v1";
    } else {
      base = cfg?.baseUrl ?? (isAnthropic ? "https://api.anthropic.com/v1" : DEFAULT_BASE);
    }
  }
  base = base.replace(/\/+$/, "");

  // Only sent when explicitly set: newer Claude models reject temperature below 1.
  const temperature = process.env.VAPT_LLM_TEMPERATURE ? Number(process.env.VAPT_LLM_TEMPERATURE) : undefined;
  return { base, model, key, temperature, isAnthropic };
}

function headers(key: string | undefined): Record<string, string> {
  return { "content-type": "application/json", ...(key ? { authorization: `Bearer ${key}` } : {}) };
}

/**
 * Format request URL, headers, and payload according to provider (Anthropic native messages vs OpenAI chat completions).
 */
export function buildLlmRequest(messages: ChatMessage[], stream = false): {
  url: string;
  headers: Record<string, string>;
  body: string;
  isAnthropic: boolean;
} {
  const { base, model, key, temperature, isAnthropic } = llmConfig();
  if (isAnthropic) {
    const url = base.endsWith("/messages")
      ? base
      : base.endsWith("/v1")
        ? `${base}/messages`
        : `${base}/v1/messages`;

    const systemParts: string[] = [];
    const nonSystem: Array<{ role: "user" | "assistant"; content: string }> = [];
    for (const m of messages) {
      if (m.role === "system") {
        systemParts.push(m.content);
      } else {
        nonSystem.push({ role: m.role, content: m.content });
      }
    }
    if (nonSystem.length === 0) {
      nonSystem.push({ role: "user", content: "Proceed." });
    }

    const payload: Record<string, unknown> = {
      model,
      messages: nonSystem,
      max_tokens: Number(process.env.VAPT_LLM_MAX_TOKENS) || 4096,
      ...(systemParts.length > 0 ? { system: systemParts.join("\n\n") } : {}),
      ...(temperature !== undefined ? { temperature } : {}),
      ...(stream ? { stream: true } : {}),
    };

    return {
      url,
      headers: {
        "content-type": "application/json",
        ...(key ? { "x-api-key": key } : {}),
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(payload),
      isAnthropic: true,
    };
  }

  return {
    url: `${base}/chat/completions`,
    headers: headers(key),
    body: JSON.stringify({
      model,
      messages,
      ...(temperature !== undefined ? { temperature } : {}),
      ...(stream ? { stream: true } : {}),
    }),
    isAnthropic: false,
  };
}

/** Rough token estimate (~4 chars per token for typical English text/JSON). */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/** Estimate total input tokens across a sequence of ChatMessages. */
export function estimateMessageTokens(messages: ChatMessage[]): number {
  return messages.reduce((acc, m) => acc + estimateTokens(m.content) + 4, 0);
}

async function waitRetry(res?: Response): Promise<void> {
  const retryHeader = res?.headers?.get("retry-after");
  const parsed = retryHeader ? Number(retryHeader) * 1000 : null;
  const configured = process.env.VAPT_LLM_RETRY_DELAY_MS ? Number(process.env.VAPT_LLM_RETRY_DELAY_MS) : undefined;
  const fallback = process.env.NODE_ENV === "test" || process.env.VAPT_LLM_MODEL === "stub" ? 0 : 1000;
  const delayMs = Math.min(parsed ?? configured ?? fallback, 30_000);
  if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
}

/** One chat completion against any OpenAI-compatible or Anthropic endpoint. One retry on network/429/5xx. */
export async function chat(messages: ChatMessage[]): Promise<string> {
  const timeoutMs = Number(process.env.VAPT_LLM_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;
  const req = buildLlmRequest(messages, false);
  let lastErr: Error | null = null;

  for (let attempt = 0; attempt < 2; attempt++) {
    let res: Response;
    try {
      res = await fetch(req.url, {
        method: "POST",
        headers: req.headers,
        body: req.body,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      lastErr = e instanceof Error ? e : new Error(String(e)); // network error or timeout — retry
      await waitRetry();
      continue;
    }
    if (!res.ok) {
      const detail = (await res.text()).slice(0, 300);
      lastErr = new Error(`LLM HTTP ${res.status}: ${detail}`);
      if (RETRYABLE.has(res.status)) {
        await waitRetry(res);
        continue;
      }
      throw lastErr;
    }
    const json = ((await res.json()) as any);
    let content: string | undefined;
    if (typeof json?.choices?.[0]?.message?.content === "string") {
      content = json.choices[0].message.content;
    } else if (Array.isArray(json?.content)) {
      content = json.content.map((c: any) => c?.text ?? "").join("");
    }
    if (typeof content !== "string" || !content.trim()) throw new Error("LLM returned empty content");
    return content;
  }
  throw lastErr ?? new Error("LLM call failed");
}

/** Streaming chat completion (SSE). One connection-level retry on network/429/5xx; no retry once tokens flow. */
export async function* chatStream(messages: ChatMessage[]): AsyncGenerator<string> {
  const timeoutMs = Number(process.env.VAPT_LLM_TIMEOUT_MS) || DEFAULT_STREAM_TIMEOUT_MS;
  const req = buildLlmRequest(messages, true);

  // Connection-level retry — same policy as chat(): one retry on network errors or retryable HTTP status.
  let res!: Response;
  let lastErr: Error | null = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      res = await fetch(req.url, {
        method: "POST",
        headers: req.headers,
        body: req.body,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      lastErr = e instanceof Error ? e : new Error(String(e));
      await waitRetry();
      continue;
    }
    if (!res.ok) {
      const detail = (await res.text()).slice(0, 300);
      lastErr = new Error(`LLM HTTP ${res.status}: ${detail}`);
      if (RETRYABLE.has(res.status)) {
        await waitRetry(res);
        continue;
      }
      throw lastErr;
    }
    lastErr = null;
    break;
  }
  if (lastErr) throw lastErr;
  if (!res.body) throw new Error("LLM returned no response body");

  // Yield SSE deltas — works with both OpenAI choices[0].delta.content and Anthropic text_delta.
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop()!;
      for (const raw of lines) {
        const line = raw.trim();
        if (!line.startsWith("data:")) continue;
        const payload = line.slice(5).trim();
        if (payload === "[DONE]") return;
        try {
          const parsed = JSON.parse(payload);
          if (parsed?.type === "message_stop") return;
          const delta =
            parsed?.choices?.[0]?.delta?.content ??
            (parsed?.type === "content_block_delta" && parsed?.delta?.type === "text_delta"
              ? parsed.delta.text
              : undefined);
          if (typeof delta === "string" && delta) yield delta;
        } catch {
          /* not a complete JSON frame — ignore */
        }
      }
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      /* stream already closed */
    }
  }
}

/** Parse a JSON object out of an LLM reply, tolerating prose wrappers and ``` fences. */
export function parseJsonLoose(text: string): unknown {
  const cleaned = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "").trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  const candidates = start >= 0 && end > start ? [cleaned, cleaned.slice(start, end + 1)] : [cleaned];
  for (const c of candidates) {
    try {
      return JSON.parse(c);
    } catch {
      /* try next candidate */
    }
  }
  throw new Error("LLM response was not parseable JSON");
}