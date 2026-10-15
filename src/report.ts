import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DATA_RULE, SYSTEM_PROMPT, dataTag } from "./agent-prompt.js";
import { findCveIds } from "./cve-cache.js";
import { chat } from "./llm.js";
import { type TriageCtx, triageFindingJson } from "./triage.js";
import type { CveEntry, Finding, TriageResult } from "./types.js";
import { progressBar } from "./ui.js";

const TRIAGE_CONCURRENCY = 4;

export interface ReportOutcome {
  markdown: string;
  failures: string[];
}

/** Triage every finding individually, then one synthesis pass assembles the REPORT MODE sections. */
export async function buildReport(
  findings: Finding[],
  ctx: TriageCtx,
  log?: (msg: string) => void,
): Promise<ReportOutcome> {
  const { results, failures } = await triageAll(findings, ctx, log);
  if (results.length === 0) throw new Error("no finding could be triaged — no report produced");
  const markdown = await synthesize(findings, results, failures, ctx, log);
  return { markdown, failures };
}

/** Write the report under the standard name scheme; returns the file path. */
export function saveReport(markdown: string, outDir: string): string {
  mkdirSync(outDir, { recursive: true });
  const file = join(outDir, `vapt-report-${new Date().toISOString().slice(0, 19).replace(/[:-]/g, "")}.md`);
  writeFileSync(file, markdown + "\n");
  return file;
}

/** Write an HTML report; returns the file path. */
export function saveReportHtml(html: string, outDir: string): string {
  mkdirSync(outDir, { recursive: true });
  const file = join(outDir, `vapt-report-${new Date().toISOString().slice(0, 19).replace(/[:-]/g, "")}.html`);
  writeFileSync(file, html + "\n");
  return file;
}

/** Up to TRIAGE_CONCURRENCY calls in flight; results keep input (severity) order. */
async function triageAll(
  findings: Finding[],
  ctx: TriageCtx,
  log?: (msg: string) => void,
): Promise<{ results: TriageResult[]; failures: string[] }> {
  const results: (TriageResult | null)[] = new Array(findings.length).fill(null);
  const failures: string[] = [];
  let next = 0;
  let completed = 0;
  const worker = async () => {
    while (next < findings.length) {
      const i = next++;
      const f = findings[i]!;
      try {
        results[i] = await triageFindingJson(f, ctx);
      } catch (e) {
        failures.push(`${f.id}: ${(e as Error).message}`);
      } finally {
        completed++;
        log?.(`triaged ${progressBar(completed, findings.length)} ${f.id} (${f.severity ?? "?"})`);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(TRIAGE_CONCURRENCY, findings.length) }, worker));
  return { results: results.filter((r): r is TriageResult => r !== null), failures };
}

async function synthesize(
  findings: Finding[],
  results: TriageResult[],
  failures: string[],
  ctx: TriageCtx,
  log?: (msg: string) => void,
): Promise<string> {
  log?.(`synthesizing report from ${results.length} triage result(s)`);
  const compact = findings.map(({ raw: _raw, ...rest }) => rest); // the report must not carry evidence
  const entries = findCveIds(JSON.stringify({ findings: compact, results }))
    .map((id) => ctx.cache.get(id))
    .filter((e): e is CveEntry => Boolean(e));
  const failureNote = failures.length
    ? `\n\nThese findings could not be triaged (processing error) — list each under its severity flagged as "not triaged — processing error": ${failures.join("; ")}`
    : "";
  const content = await chat([
    { role: "system", content: SYSTEM_PROMPT },
    {
      role: "user",
      content: [
        "Compose the full VAPT report (REPORT MODE structure, sections 1-5) from the pre-computed triage results below. Use them as the substance of section 3 — do not re-triage. Group findings by severity.",
        "Markdown only. No exploit payloads, no raw traffic, no credentials — state that evidence is held in a separate access-controlled evidence log instead.",
        DATA_RULE + failureNote,
        dataTag("scope", ctx.scope),
        dataTag("findings", compact),
        dataTag("triage-results", results),
        dataTag("cve-cache", entries),
      ].join("\n\n"),
    },
  ]);
  return content.trim();
}

/** Simple markdown-to-HTML converter with zero external dependencies. */
export function markdownToHtml(md: string): string {
  let html = md
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  html = html.replace(/```([a-z0-9_-]*)\n([\s\S]*?)```/g, (_m, lang, code) => {
    return `<pre><code class="language-${lang}">${code.trim()}</code></pre>`;
  });

  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/^#### (.*$)/gim, "<h4>$1</h4>");
  html = html.replace(/^### (.*$)/gim, "<h3>$1</h3>");
  html = html.replace(/^## (.*$)/gim, "<h2>$1</h2>");
  html = html.replace(/^# (.*$)/gim, "<h1>$1</h1>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  html = html.replace(/^---$/gim, "<hr/>");

  html = html.replace(/((?:^\|.*\|\r?\n)+)/gm, (table) => {
    const lines = table.trim().split("\n");
    if (lines.length < 2) return table;
    const header = lines[0]!.split("|").slice(1, -1).map((c) => `<th>${c.trim()}</th>`).join("");
    const bodyLines = lines.slice(2);
    const body = bodyLines
      .map((row) => `<tr>${row.split("|").slice(1, -1).map((c) => `<td>${c.trim()}</td>`).join("")}</tr>`)
      .join("");
    return `<table><thead><tr>${header}</tr></thead><tbody>${body}</tbody></table>`;
  });

  html = html.replace(/^[-*] (.*$)/gim, "<li>$1</li>");
  html = html.replace(/((?:<li>.*<\/li>\s*)+)/gim, "<ul>$1</ul>");

  const blocks = html.split(/\n{2,}/);
  html = blocks
    .map((b) => {
      const trimmed = b.trim();
      if (!trimmed) return "";
      if (/^<(h[1-6]|table|pre|ul|ol|hr|blockquote)/i.test(trimmed)) return trimmed;
      return `<p>${trimmed.replace(/\n/g, "<br/>")}</p>`;
    })
    .join("\n");

  return html;
}

/** Generate a complete standalone responsive HTML report. */
export function renderReportHtml(markdown: string, title = "VAPT Assessment Report"): string {
  const bodyHtml = markdownToHtml(markdown);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>${title}</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --text: #e6edf3;
      --text-dim: #8b949e;
      --border: #30363d;
      --accent: #58a6ff;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f6f8fa;
        --card-bg: #ffffff;
        --text: #1f2328;
        --text-dim: #656d76;
        --border: #d0d7de;
        --accent: #0969da;
      }
    }
    * { box-sizing: border-box; }
    body {
      font-family: var(--font);
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 2rem 1rem;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 2.5rem;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    h1, h2, h3, h4 { color: var(--text); margin-top: 1.8rem; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
    h1 { margin-top: 0; font-size: 2rem; border-bottom: 2px solid var(--accent); }
    h2 { font-size: 1.5rem; }
    h3 { font-size: 1.25rem; border-bottom: none; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    pre { background: var(--bg); padding: 1rem; border-radius: 6px; overflow-x: auto; border: 1px solid var(--border); }
    code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: 0.9em; }
    table { width: 100%; border-collapse: collapse; margin: 1.5rem 0; font-size: 0.95rem; }
    th, td { border: 1px solid var(--border); padding: 0.6rem 0.8rem; text-align: left; }
    th { background: var(--bg); font-weight: 600; }
    hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }
    ul { padding-left: 1.5rem; }
    li { margin-bottom: 0.3rem; }
  </style>
</head>
<body>
  <div class="container">
    ${bodyHtml}
  </div>
</body>
</html>`;
}