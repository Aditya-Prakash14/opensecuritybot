export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

const RETRYABLE = new Set([429, 500, 502, 503, 504]);
const DEFAULT_BASE = "https://api.openai.com/v1";
const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_STREAM_TIMEOUT_MS = 300_000;

function llmConfig(): { base: string; model: string; key: string | undefined } {
  const base = (process.env.VAPT_LLM_BASE_URL ?? DEFAULT_BASE).replace(/\/+$/, "");
  const key = process.env.VAPT_LLM_API_KEY;
  const model = process.env.VAPT_LLM_MODEL;
  if (!model) throw new Error("VAPT_LLM_MODEL is not set (e.g. gpt-4o-mini, llama3.1, anthropic/claude-sonnet)");
  return { base, model, key };
}

function headers(key: string | undefined): Record<string, string> {
  return { "content-type": "application/json", ...(key ? { authorization: `Bearer ${key}` } : {}) };
}

/** One chat completion against any OpenAI-compatible endpoint. One retry on network/429/5xx. */
export async function chat(messages: ChatMessage[]): Promise<string> {
  const { base, model, key } = llmConfig();
  const timeoutMs = Number(process.env.VAPT_LLM_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;
  const body = JSON.stringify({ model, messages, temperature: 0.2 });
  let lastErr: Error | null = null;

  for (let attempt = 0; attempt < 2; attempt++) {
    let res: Response;
    try {
      res = await fetch(`${base}/chat/completions`, {
        method: "POST",
        headers: headers(key),
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      lastErr = e instanceof Error ? e : new Error(String(e)); // network error or timeout — retry
      continue;
    }
    if (!res.ok) {
      const detail = (await res.text()).slice(0, 300);
      lastErr = new Error(`LLM HTTP ${res.status}: ${detail}`);
      if (RETRYABLE.has(res.status)) continue;
      throw lastErr;
    }
    const content = ((await res.json()) as any)?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || !content.trim()) throw new Error("LLM returned empty content");
    return content;
  }
  throw lastErr ?? new Error("LLM call failed");
}

/** Streaming chat completion (SSE). Yields content deltas as they arrive. No retry once streaming. */
export async function* chatStream(messages: ChatMessage[]): AsyncGenerator<string> {
  const { base, model, key } = llmConfig();
  const timeoutMs = Number(process.env.VAPT_LLM_TIMEOUT_MS) || DEFAULT_STREAM_TIMEOUT_MS;
  const res = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: headers(key),
    body: JSON.stringify({ model, messages, temperature: 0.2, stream: true }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`LLM HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  if (!res.body) throw new Error("LLM returned no response body");

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
          const delta = JSON.parse(payload)?.choices?.[0]?.delta?.content;
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