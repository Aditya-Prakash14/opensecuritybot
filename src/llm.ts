export interface ChatMessage {
  role: "system" | "user";
  content: string;
}

const RETRYABLE = new Set([429, 500, 502, 503, 504]);
const DEFAULT_BASE = "https://api.openai.com/v1";

/** One chat completion against any OpenAI-compatible endpoint. One retry on network/429/5xx. */
export async function chat(messages: ChatMessage[]): Promise<string> {
  const base = (process.env.VAPT_LLM_BASE_URL ?? DEFAULT_BASE).replace(/\/+$/, "");
  const model = process.env.VAPT_LLM_MODEL;
  const key = process.env.VAPT_LLM_API_KEY;
  if (!model) throw new Error("VAPT_LLM_MODEL is not set (e.g. gpt-4o-mini, llama3.1, anthropic/claude-sonnet)");

  const body = JSON.stringify({ model, messages, temperature: 0.2 });
  let lastErr: Error | null = null;

  for (let attempt = 0; attempt < 2; attempt++) {
    let res: Response;
    try {
      res = await fetch(`${base}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(key ? { authorization: `Bearer ${key}` } : {}),
        },
        body,
      });
    } catch (e) {
      lastErr = e instanceof Error ? e : new Error(String(e)); // network error — retry
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