import type { TriageResult } from "./types.js";

const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

function ansi(open: string): (s: string) => string {
  return (s) => (process.stdout.isTTY ? `\x1b[${open}m${s}\x1b[0m` : s);
}

export const bold = ansi("1");
export const dim = ansi("2");
export const red = ansi("31");
export const green = ansi("32");
export const yellow = ansi("33");
export const cyan = ansi("36");

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

/** Braille spinner on stderr (never stdout). No-op on non-TTY. */
export function spinner(text: string): { stop: (final?: string) => void } {
  if (!process.stderr.isTTY) {
    return { stop: (final) => { if (final) process.stderr.write(final + "\n"); } };
  }
  let frame = 0;
  const timer = setInterval(() => {
    frame = (frame + 1) % frames.length;
    process.stderr.write(`\r\x1b[2K${dim(frames[frame]!)} ${text}`);
  }, 80);
  timer.unref();
  return {
    stop: (final) => {
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
export async function streamMarkdown(chunks: AsyncIterable<string>): Promise<string> {
  let full = "";
  let buf = "";
  for await (const chunk of chunks) {
    full += chunk;
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      process.stdout.write(renderMarkdownLine(buf.slice(0, nl)) + "\n");
      buf = buf.slice(nl + 1);
    }
  }
  if (buf) process.stdout.write(renderMarkdownLine(buf) + "\n");
  return full;
}

/** Deterministic terminal rendering of a structured triage result. */
export function formatTriageResult(r: TriageResult): string {
  const lines: string[] = [
    `triage     ${r.triage.isLikelyTruePositive ? green("likely true positive") : yellow("likely false positive")} · severity ${severityColor(r.triage.adjustedSeverity)(r.triage.adjustedSeverity)} · owasp ${r.triage.owaspCategory ?? "—"} · confidence ${r.confidence}`,
  ];
  if (r.flaggedForManualReview) lines.push(yellow("flagged    for manual review"));
  lines.push("", bold("reasoning"), r.triage.reasoning, "", bold("explanation"), r.explanation, "", `${bold("remediation")} — ${r.remediation.summary}`);
  for (const s of r.remediation.steps) lines.push(`  • ${s}`);
  if (r.remediation.references.length) {
    lines.push("", bold("references"));
    for (const ref of r.remediation.references) lines.push(`  ${dim(ref)}`);
  }
  return lines.join("\n");
}