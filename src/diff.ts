import { findingSignature, severityRank } from "./findings.js";
import { escapeHtml, markdownToHtml } from "./report.js";
import type { Finding } from "./types.js";
import { bold, dim, green, red, yellow } from "./ui.js";

export interface PersistentFinding {
  baseline: Finding;
  current: Finding;
  severityDrift: "escalated" | "downgraded" | "unchanged";
  previousSeverity: string;
  currentSeverity: string;
}

export interface DiffResult {
  baselineTotal: number;
  currentTotal: number;
  resolved: Finding[];
  new: Finding[];
  persistent: PersistentFinding[];
  remediationRate: number;
}

/**
 * Compare baseline findings against re-test findings to calculate remediation progress.
 */
export function compareFindings(baseline: Finding[], current: Finding[]): DiffResult {
  const currentMap = new Map<string, Finding>();
  for (const f of current) {
    currentMap.set(findingSignature(f), f);
  }

  const baselineMap = new Map<string, Finding>();
  const resolved: Finding[] = [];
  const persistent: PersistentFinding[] = [];

  for (const b of baseline) {
    const sig = findingSignature(b);
    baselineMap.set(sig, b);
    const curr = currentMap.get(sig);
    if (!curr) {
      resolved.push(b);
    } else {
      const bRank = severityRank(b.severity);
      const cRank = severityRank(curr.severity);
      let severityDrift: "escalated" | "downgraded" | "unchanged" = "unchanged";
      if (cRank > bRank) severityDrift = "escalated";
      else if (cRank < bRank) severityDrift = "downgraded";

      persistent.push({
        baseline: b,
        current: curr,
        severityDrift,
        previousSeverity: b.severity ?? "unknown",
        currentSeverity: curr.severity ?? "unknown",
      });
    }
  }

  const newFindings: Finding[] = [];
  for (const c of current) {
    const sig = findingSignature(c);
    if (!baselineMap.has(sig)) {
      newFindings.push(c);
    }
  }

  const baselineTotal = baseline.length;
  const currentTotal = current.length;
  const remediationRate = baselineTotal > 0 ? Number(((resolved.length / baselineTotal) * 100).toFixed(1)) : 0;

  return {
    baselineTotal,
    currentTotal,
    resolved,
    new: newFindings,
    persistent,
    remediationRate,
  };
}

/**
 * Render a remediation diff report as GitHub-flavored Markdown.
 */
export function renderDiffMarkdown(
  diff: DiffResult,
  options?: { baselinePath?: string; currentPath?: string; engagement?: string },
): string {
  const title = options?.engagement ? `${options.engagement} — Remediation Delta Report` : "VAPT Remediation Delta Report";
  const lines: string[] = [
    `# ${title}`,
    "",
    `_Generated on ${new Date().toISOString().slice(0, 10)}_`,
    "",
    "## 1. Executive Remediation Summary",
    "",
    `| Metric | Count | Details |`,
    `| :--- | :--- | :--- |`,
    `| **Baseline Findings** | ${diff.baselineTotal} | Initial assessment volume (${options?.baselinePath ?? "baseline"}) |`,
    `| **Current Findings** | ${diff.currentTotal} | Re-test assessment volume (${options?.currentPath ?? "current"}) |`,
    `| **Resolved (Remediated)** | ${diff.resolved.length} | Successfully closed vulnerabilities |`,
    `| **Persistent (Unresolved)** | ${diff.persistent.length} | Still observed in current re-test |`,
    `| **New Findings** | ${diff.new.length} | Newly introduced or detected issues |`,
    `| **Remediation Rate** | **${diff.remediationRate}%** | Proportion of baseline findings fixed |`,
    "",
  ];

  if (diff.resolved.length > 0) {
    lines.push("## 2. Resolved Findings (Verified Remediated)", "");
    lines.push("| ID | Target | Title | Baseline Severity |");
    lines.push("| :--- | :--- | :--- | :--- |");
    for (const f of diff.resolved) {
      lines.push(`| \`${f.id}\` | \`${f.target}\` | ${f.title ?? "—"} | **${(f.severity ?? "info").toUpperCase()}** |`);
    }
    lines.push("");
  }

  if (diff.persistent.length > 0) {
    lines.push("## 3. Persistent Findings (Unresolved / In Progress)", "");
    lines.push("| ID | Target | Title | Baseline Severity | Current Severity | Status |");
    lines.push("| :--- | :--- | :--- | :--- | :--- | :--- |");
    for (const p of diff.persistent) {
      const status =
        p.severityDrift === "escalated"
          ? "⚠️ Escalated"
          : p.severityDrift === "downgraded"
            ? "⬇️ Downgraded"
            : "Unchanged";
      lines.push(
        `| \`${p.current.id}\` | \`${p.current.target}\` | ${p.current.title ?? "—"} | ${(p.previousSeverity).toUpperCase()} | **${(p.currentSeverity).toUpperCase()}** | ${status} |`,
      );
    }
    lines.push("");
  }

  if (diff.new.length > 0) {
    lines.push("## 4. Newly Introduced Findings", "");
    lines.push("| ID | Target | Title | Severity |");
    lines.push("| :--- | :--- | :--- | :--- |");
    for (const f of diff.new) {
      lines.push(`| \`${f.id}\` | \`${f.target}\` | ${f.title ?? "—"} | **${(f.severity ?? "info").toUpperCase()}** |`);
    }
    lines.push("");
  }

  lines.push("## 5. Remediation Recommendations", "");
  if (diff.persistent.length === 0 && diff.new.length === 0) {
    lines.push("All baseline vulnerabilities have been successfully remediated, and no new issues were detected. Target posture is sound.");
  } else {
    lines.push("1. **Prioritize persistent critical and high issues**: Retain engineering resources to address lingering findings.");
    if (diff.new.length > 0) {
      lines.push("2. **Investigate regression causes**: Examine newly detected findings to ensure recent deployment changes did not bypass security controls.");
    }
    lines.push("3. **Schedule final verification**: Conduct a follow-up assessment once outstanding remediation actions conclude.");
  }
  lines.push("");

  return lines.join("\n");
}

/**
 * Render a complete standalone HTML document with badges and responsive tables for diff.
 */
export function renderDiffHtml(diff: DiffResult, options?: { baselinePath?: string; currentPath?: string; engagement?: string }): string {
  const md = renderDiffMarkdown(diff, options);
  const title = options?.engagement ? `${options.engagement} — Remediation Delta` : "Remediation Delta Report";
  const body = markdownToHtml(md);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #121826;
      --text: #e2e8f0;
      --text-dim: #94a3b8;
      --border: #1e293b;
      --primary: #38bdf8;
      --green: #22c55e;
      --red: #ef4444;
      --amber: #f59e0b;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      margin: 0;
      padding: 2rem 1rem;
      line-height: 1.6;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background: var(--card-bg);
      padding: 2.5rem;
      border-radius: 12px;
      border: 1px solid var(--border);
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }
    h1, h2, h3 { color: #f8fafc; font-weight: 700; margin-top: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    h1 { font-size: 2rem; border: none; margin-top: 0; }
    a { color: var(--primary); text-decoration: none; }
    code { font-family: var(--font-mono); font-size: 0.9em; background: rgba(255,255,255,0.06); padding: 0.2em 0.4em; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; margin: 1.5rem 0; font-size: 0.95rem; }
    th, td { border: 1px solid var(--border); padding: 0.75rem 1rem; text-align: left; }
    th { background: rgba(255,255,255,0.03); color: #f1f5f9; font-weight: 600; }
    tr:nth-child(even) { background: rgba(255,255,255,0.015); }
    .badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
    .badge-green { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }
    .badge-red { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-amber { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
    .footer { margin-top: 3rem; text-align: center; font-size: 0.85rem; color: var(--text-dim); }
  </style>
</head>
<body>
  <div class="container">
    ${body}
    <div class="footer">
      Generated by <strong>opensecuritybot</strong> • Authorized VAPT Delta Verification
    </div>
  </div>
</body>
</html>`;
}

/**
 * Print a concise ANSI-colored diff summary to stderr (stdout is reserved for data).
 */
export function printDiffSummary(diff: DiffResult): void {
  console.error(`\n${bold("Remediation Delta Summary")}`);
  console.error(dim("─".repeat(50)));
  console.error(`  Baseline Findings:    ${bold(String(diff.baselineTotal))}`);
  console.error(`  Current Findings:     ${bold(String(diff.currentTotal))}`);
  console.error(`  Resolved (Remediated): ${green(bold(String(diff.resolved.length)))}`);
  console.error(`  Persistent (Pending): ${diff.persistent.length > 0 ? yellow(bold(String(diff.persistent.length))) : green("0")}`);
  console.error(`  New Findings:         ${diff.new.length > 0 ? red(bold(String(diff.new.length))) : green("0")}`);
  console.error(`  Remediation Rate:     ${green(bold(`${diff.remediationRate}%`))}`);
  console.error(dim("─".repeat(50)) + "\n");
}
