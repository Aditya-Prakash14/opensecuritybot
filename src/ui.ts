import type { TriageResult } from "./types.js";

function ansi(open: string): (s: string) => string {
  return (s) => (process.stdout.isTTY ? `\x1b[${open}m${s}\x1b[0m` : s);
}

export const bold = ansi("1");
export const dim = ansi("2");
export const red = ansi("31");
export const green = ansi("32");
export const yellow = ansi("33");
export const cyan = ansi("36");
const orange = ansi("38;5;208");

export function severityColor(severity: string | undefined): (s: string) => string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return ansi("1;35");
    case "high":
      return ansi("31");
    case "medium":
      return ansi("33");
    case "low":
      return ansi("36");
    default:
      return dim;
  }
}

export function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

export function visibleLength(s: string): number {
  return stripAnsi(s).length;
}

function padTo(s: string, width: number): string {
  const gap = width - visibleLength(s);
  return gap > 0 ? s + " ".repeat(gap) : s;
}

/** Rounded-corner box with an optional title, Claude-style. */
export function box(lines: string[], title?: string): string {
  const contentWidth = Math.max(0, ...lines.map(visibleLength));
  const width = Math.max(contentWidth, title ? visibleLength(title) + 3 : 0) + 4;
  const mid = width - 2;
  const head = title ? `─ ${title} ` : "─";
  const topMid = head + "─".repeat(Math.max(0, mid - visibleLength(head)));
  const rows = [
    `╭${topMid}╮`,
    ...lines.map((l) => `│ ${padTo(l, width - 4)} │`),
    `╰${"─".repeat(mid)}╯`,
  ];
  return rows.map(dim).join("\n");
}

const starFrames = ["✻", "✽", "✾", "✳", "✢"];

/** Claude-style thinking indicator on stderr: ✻ verb… (Ns). No-op on non-TTY. */
export function spinner(text: string): { stop: (final?: string) => void } {
  if (!process.stderr.isTTY) {
    return { stop: (final) => { if (final) process.stderr.write(final + "\n"); } };
  }
  const started = Date.now();
  let frame = 0;
  let stopped = false;
  const render = () => {
    const seconds = Math.floor((Date.now() - started) / 1000);
    process.stderr.write(`\r\x1b[2K${orange(starFrames[frame % starFrames.length]!)} ${text}… ${dim(`(${seconds}s)`)}`);
  };
  const timer = setInterval(() => {
    frame++;
    render();
  }, 120);
  timer.unref();
  render();
  return {
    stop: (final) => {
      if (stopped) return;
      stopped = true;
      clearInterval(timer);
      process.stderr.write("\r\x1b[2K");
      if (final) process.stderr.write(final + "\n");
    },
  };
}

/** Minimal markdown-to-ANSI for a single line: headings, bold, code spans, bullets. */
export function renderMarkdownLine(line: string): string {
  if (/^\s*#{1,6}\s/.test(line)) return bold(cyan(line.replace(/^\s*#{1,6}\s+/, "")));
  let out = line.replace(/\*\*([^*]+)\*\*/g, (_m, t: string) => bold(t));
  out = out.replace(/`([^`]+)`/g, (_m, t: string) => dim(t));
  out = out.replace(/^(\s*)[-*]\s+/, (_m, ws: string) => `${ws}• `);
  return out;
}

/** Stream chunks to stdout, rendering markdown line by line. Returns the raw text. */
export async function streamMarkdown(
  chunks: AsyncIterable<string>,
  opts: { onFirstChunk?: () => void } = {},
): Promise<string> {
  let first = true;
  let full = "";
  let buf = "";
  for await (const chunk of chunks) {
    if (first) {
      first = false;
      opts.onFirstChunk?.();
    }
    full += chunk;
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      process.stdout.write(renderMarkdownLine(buf.slice(0, nl)) + "\n");
      buf = buf.slice(nl + 1);
    }
  }
  if (first) opts.onFirstChunk?.(); // empty stream — clear the indicator anyway
  if (buf) process.stdout.write(renderMarkdownLine(buf) + "\n");
  return full;
}

/** Boxed, severity-colored terminal card for a structured triage result. */
export function formatTriageResult(r: TriageResult): string {
  const lines: string[] = [
    `${dim("triage")}     ${r.triage.isLikelyTruePositive ? green("likely true positive") : yellow("likely false positive")} · severity ${severityColor(r.triage.adjustedSeverity)(r.triage.adjustedSeverity)} · owasp ${r.triage.owaspCategory ?? "—"} · confidence ${r.confidence}`,
  ];
  if (r.flaggedForManualReview) lines.push(`${dim("flagged")}    ${yellow("for manual review")}`);
  lines.push(
    "",
    bold("reasoning"),
    r.triage.reasoning,
    "",
    bold("explanation"),
    r.explanation,
    "",
    `${bold("remediation")} ${dim("—")} ${r.remediation.summary}`,
  );
  for (const s of r.remediation.steps) lines.push(`  • ${s}`);
  if (r.remediation.references.length) {
    lines.push("", bold("references"));
    for (const ref of r.remediation.references) lines.push(`  ${dim(ref)}`);
  }
  const title = `${r.findingId} · ${severityColor(r.triage.adjustedSeverity)(r.triage.adjustedSeverity)}${r.triage.owaspCategory ? ` · ${r.triage.owaspCategory}` : ""}`;
  return box(lines, title);
}