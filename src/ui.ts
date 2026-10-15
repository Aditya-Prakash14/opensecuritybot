import type { TriageResult } from "./types.js";

function ansi(open: string): (s: string) => string {
  return (s) => (process.stdout.isTTY || process.stderr.isTTY ? `\x1b[${open}m${s}\x1b[0m` : s);
}

export const bold = ansi("1");
export const dim = ansi("2");
export const italic = ansi("3");
export const underline = ansi("4");
export const red = ansi("31");
export const green = ansi("32");
export const yellow = ansi("33");
export const blue = ansi("34");
export const magenta = ansi("35");
export const cyan = ansi("36");

// Claude-Code-inspired warm & crisp terminal palette
export const coral = ansi("38;5;209");
export const amber = ansi("38;5;214");
export const copper = ansi("38;5;173");
export const purple = ansi("38;5;141");
export const emerald = ansi("38;5;78");
export const ruby = ansi("38;5;203");
export const slate = ansi("38;5;244");
export const ice = ansi("38;5;117");

export function severityColor(severity: string | undefined): (s: string) => string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return ansi("1;38;5;198");
    case "high":
      return ansi("1;38;5;203");
    case "medium":
      return ansi("1;38;5;214");
    case "low":
      return ansi("38;5;117");
    default:
      return dim;
  }
}

/** High-visibility colored pill badge for severity. */
export function severityBadge(severity?: string): string {
  const s = (severity ?? "unknown").toUpperCase();
  switch (s.toLowerCase()) {
    case "critical":
      return ansi("1;97;41")(` CRITICAL `);
    case "high":
      return ansi("1;97;41")(` HIGH `);
    case "medium":
      return ansi("1;97;43")(` MEDIUM `);
    case "low":
      return ansi("1;97;44")(` LOW `);
    default:
      return ansi("1;97;100")(` ${s} `);
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
  const width = Math.max(contentWidth, title ? visibleLength(title) + 4 : 0) + 4;
  const mid = width - 2;
  const head = title ? `─ ${title} ` : "─";
  const topMid = head + "─".repeat(Math.max(0, mid - visibleLength(head)));
  const rows = [
    dim(`╭${topMid}╮`),
    ...lines.map((l) => `${dim("│")} ${padTo(l, width - 4)} ${dim("│")}`),
    dim(`╰${"─".repeat(mid)}╯`),
  ];
  return rows.join("\n");
}

/**
 * Claude Code style avatar and brand banner.
 */
export function renderAvatar(version = "0.4.0"): string {
  return [
    `  ${coral("╭──────────────╮")}  ${bold("opensecuritybot")} ${dim(`v${version}`)}`,
    `  ${coral("│")}  ${amber("⬡")}  ${coral("🛡️")}  ${amber("⬡")}   ${coral("│")}  ${cyan("The AI Security Reasoning Layer")}`,
    `  ${coral("│")}  ${dim("SECURITY")}    ${coral("│")}  ${dim("Local reasoning · Scope-safe · Zero-exploit")}`,
    `  ${coral("╰──────────────╯")}  ${dim("Authorized VAPT engagements only")}`,
  ].join("\n");
}

/**
 * Claude Code style dashboard card displaying active engagement telemetry.
 */
export function renderHeroCard(info: {
  engagement?: string;
  inScopeCount: number;
  skippedCount?: number;
  reportsDir?: string;
  model?: string;
  provider?: string;
}): string {
  const rows = [
    `${dim("engagement")}  ${info.engagement ? bold(info.engagement) : yellow("None specified")}`,
    `${dim("findings")}    ${green(`● ${info.inScopeCount} in-scope`)}${info.skippedCount ? ` · ${yellow(`▲ ${info.skippedCount} skipped (out of scope)`)}` : ""}`,
    `${dim("provider")}    ${cyan(info.provider ?? "configured")} ${info.model ? dim(`(${info.model})`) : ""}`,
    `${dim("reports")}     ${info.reportsDir ? dim(info.reportsDir) : dim("./report/")}`,
  ];
  return box(rows, "opensecuritybot · session");
}

/**
 * Sleek card introducing a finding being triaged.
 */
export function findingHeader(f: { id: string; target: string; title?: string; severity?: string; tool?: string }): string {
  const title = f.title ?? f.target;
  const badge = severityBadge(f.severity);
  const line1 = `${bold(f.id)} — ${title}  ${badge}`;
  const line2 = `${dim("target:")} ${cyan(f.target)}${f.tool ? `  ${dim("·  tool:")} ${dim(f.tool)}` : ""}`;
  return "\n" + box([line1, line2], `finding ${f.id}`) + "\n";
}

/** Simple ASCII/ANSI progress bar: [████████░░░░░░░░] 50% (5/10) */
export function progressBar(current: number, total: number, width = 20): string {
  const ratio = total > 0 ? Math.min(1, Math.max(0, current / total)) : 0;
  const filled = Math.round(ratio * width);
  const empty = width - filled;
  const bar = `${green("█".repeat(filled))}${dim("░".repeat(empty))}`;
  const pct = Math.round(ratio * 100);
  return `[${bar}] ${pct}% (${current}/${total})`;
}

const starFrames = ["✻", "✽", "✾", "✳", "✢", "✹"];

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
    process.stderr.write(`\r\x1b[2K${coral(starFrames[frame % starFrames.length]!)} ${text}… ${dim(`(${seconds}s)`)}`);
  };
  const timer = setInterval(() => {
    frame++;
    render();
  }, 100);
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

/** Interactive countdown timer for rate limits or delayed retries. */
export async function countdownSpinner(seconds: number, message: string): Promise<void> {
  if (!process.stderr.isTTY || seconds <= 0) {
    if (seconds > 0) await new Promise((r) => setTimeout(r, seconds * 1000));
    return;
  }
  let remaining = seconds;
  let frame = 0;
  return new Promise((resolve) => {
    const interval = setInterval(() => {
      process.stderr.write(`\r\x1b[2K${amber(starFrames[frame % starFrames.length]!)} ${message} ${bold(`${remaining}s`)} remaining…`);
      frame++;
    }, 120);
    const ticker = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(interval);
        clearInterval(ticker);
        process.stderr.write("\r\x1b[2K");
        resolve();
      }
    }, 1000);
  });
}

/** Enhanced markdown-to-ANSI line renderer: headings, bold, code, bullets, blockquotes, horizontal rules. */
export function renderMarkdownLine(line: string): string {
  // Headings
  if (/^\s*#{1,6}\s+/.test(line)) {
    return bold(coral(line.replace(/^\s*#{1,6}\s+/, "")));
  }

  // Horizontal rules
  if (/^\s*[-*_]{3,}\s*$/.test(line)) {
    return dim("─".repeat(50));
  }

  // Blockquotes
  if (/^\s*>\s*/.test(line)) {
    return `${dim("│")} ${italic(line.replace(/^\s*>\s*/, ""))}`;
  }

  let out = line;

  // Task lists
  out = out.replace(/^(\s*)[-*]\s+\[x\]\s+/i, (_m, ws: string) => `${ws}${green("✔")} `);
  out = out.replace(/^(\s*)[-*]\s+\[ \]\s+/i, (_m, ws: string) => `${ws}${dim("☐")} `);

  // Bullets
  out = out.replace(/^(\s*)[-*]\s+/, (_m, ws: string) => `${ws}• `);

  // Bold & Italic
  out = out.replace(/\*\*([^*]+)\*\*/g, (_m, t: string) => bold(t));
  out = out.replace(/\*([^*]+)\*/g, (_m, t: string) => italic(t));

  // Inline code spans
  out = out.replace(/`([^`]+)`/g, (_m, t: string) => dim(t));

  return out;
}

/** Stream chunks to stdout, rendering markdown line by line with Claude-style ⏺ marker. */
export async function streamMarkdown(
  chunks: AsyncIterable<string>,
  opts: { onFirstChunk?: () => void; prefixMarker?: boolean } = {},
): Promise<string> {
  let first = true;
  let full = "";
  let buf = "";
  for await (const chunk of chunks) {
    if (first) {
      first = false;
      opts.onFirstChunk?.();
      if (opts.prefixMarker) {
        process.stdout.write(coral("⏺ ") + "\n");
      }
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
  const badge = severityBadge(r.triage.adjustedSeverity);
  const statusPill = r.triage.isLikelyTruePositive
    ? green("likely true positive")
    : yellow("likely false positive");

  const lines: string[] = [
    `${dim("triage")}     ${statusPill} · ${badge} · confidence ${r.confidence}${r.triage.owaspCategory ? ` · owasp ${r.triage.owaspCategory}` : ""}`,
  ];
  if (r.flaggedForManualReview) {
    lines.push(`${dim("flagged")}    ${yellow("for manual review")}`);
  }
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
  const title = `triage · ${r.findingId} · ${severityColor(r.triage.adjustedSeverity)(r.triage.adjustedSeverity)}`;
  return box(lines, title);
}