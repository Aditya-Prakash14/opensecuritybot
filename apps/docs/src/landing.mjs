/**
 * Home-page content for the opensecuritybot docs site.
 * Returns the sections that layout() mounts inside <main id="main">.
 * Every claim here mirrors the README; nothing is invented.
 */

// layout.mjs re-exports landing(), so this module sits in a cycle: read SITE
// and url() inside functions only, never at module top level.
import { url, SITE } from "./layout.mjs";

const FEATURES = [
  {
    title: "Scope-safe by construction",
    text: `Out-of-scope findings are dropped in local code before any model call, every scan step re-checks its target against <code>scope.json</code>, and cloud metadata endpoints are refused even if listed.`,
  },
  {
    title: "Deterministic verification",
    text: `Programmatic replies are schema-checked, cited CVE IDs are cross-checked against your local <code>cve-cache</code>, and a malformed reply gets one corrective retry. Unverifiable claims are flagged for manual review.`,
  },
  {
    title: "Reviewed scan skills",
    text: `nmap, nuclei and httpx playbooks run argv-only — no shell string to inject into. Each step is printed, confirmed and re-checked against scope before it executes.`,
  },
  {
    title: "Reports that ship",
    text: `Markdown and HTML reports cover sections 1–5, executive summary through prioritized remediation roadmap, with methodology pulled from the execution ledger.`,
  },
  {
    title: "Any provider",
    text: `OpenAI, OpenRouter, Groq, Meta, Anthropic, Ollama or any OpenAI-compatible endpoint. The first-run wizard configures it; environment variables override it.`,
  },
  {
    title: "Execution ledger",
    text: `Every scan step appends tool, argv, exit code, duration and stdout SHA-256 to <code>report/scan-ledger.jsonl</code>, so the report shows what actually ran.`,
  },
];

const card = (feature, index) => `        <article class="card">
          <p class="card-index" aria-hidden="true">${String(index + 1).padStart(2, "0")}</p>
          <h3 class="card-title">${feature.title}</h3>
          <p class="card-text">${feature.text}</p>
        </article>`;

const TERMINAL = `        <div class="terminal">
          <div class="terminal-bar" aria-hidden="true">
            <span class="terminal-dot"></span><span class="terminal-dot"></span><span class="terminal-dot"></span>
            <span class="terminal-title">vapt — opensecuritybot</span>
          </div>
          <pre class="terminal-body" data-no-copy><span class="t-prompt">$</span> <span class="t-cmd">vapt scan --skill http-baseline --target https://app.acme.com</span>
<span class="t-out">[1/2] httpx -json -silent -u https://app.acme.com</span>
<span class="t-out">saved: findings/http-baseline-2026-10-17T15-30-11-724Z.json</span>
<span class="t-prompt">$</span> <span class="t-cmd">vapt report -f findings/... -s scope.json --html</span>
<span class="t-ok">methodology: 2 scan step(s) from the execution ledger</span> <span class="t-cursor" aria-hidden="true">▍</span></pre>
        </div>`;

export function landing() {
  return `  <section class="hero">
    <div class="hero-inner">
      <div class="hero-copy">
        <p class="micro-label">Authorized engagements only</p>
        <h1 class="hero-title">The reasoning layer between your scanner and your <span class="hl">report</span>.</h1>
        <p class="lede">Turn raw scanner findings into verified triage and a client-ready VAPT report. Scope is enforced in local code — findings outside <code>scope.json</code> never reach a model.</p>
        <div class="cta-row">
          <a class="btn btn-primary" href="${url("/docs/getting-started/")}">Read the docs</a>
          <a class="btn btn-ghost" href="${SITE.repoUrl}">View source</a>
        </div>
        <p class="install-line"><span class="install-prompt">$</span> npm i -g opensecuritybot</p>
      </div>
      <div class="hero-term">
${TERMINAL}
      </div>
    </div>
  </section>

  <section class="pipeline" aria-label="Pipeline">
    <div class="pipeline-inner">
      <ol class="pipeline-steps">
        <li class="pipe-item"><span class="pipe-step"><code>scope.json</code></span></li>
        <li class="pipe-item pipe-guard"><span class="pipe-step">scope guard</span></li>
        <li class="pipe-item"><span class="pipe-step">triage</span></li>
        <li class="pipe-item"><span class="pipe-step">verify</span></li>
        <li class="pipe-item"><span class="pipe-step">report</span></li>
      </ol>
    </div>
  </section>

  <section class="section features" aria-labelledby="features-title">
    <div class="wrap">
      <p class="kicker">Built in</p>
      <h2 class="section-title" id="features-title">Six guarantees, enforced in code</h2>
      <p class="section-lede">The model reasons about findings. Everything that has to be trusted — scope, verification, execution — happens in deterministic code around it.</p>
      <div class="feature-grid">
${FEATURES.map(card).join("\n")}
      </div>
    </div>
  </section>

  <section class="section skills-preview" aria-labelledby="skills-title">
    <div class="wrap">
      <p class="kicker">Scan skills</p>
      <h2 class="section-title" id="skills-title">Two reviewed playbooks, ready on install</h2>
      <p class="section-lede">A skill is a declarative, reviewed playbook — not an LLM-generated command. The shell never sees free-form input.</p>
      <div class="skill-list">
        <article class="skill-row">
          <div class="skill-info">
            <h3 class="skill-name">http-baseline <span class="risk risk-passive">passive</span></h3>
            <p class="skill-desc">Passive HTTP fingerprint and low-noise misconfiguration/exposure templates.</p>
          </div>
          <ul class="chips" aria-label="Tools">
            <li class="chip">httpx</li>
            <li class="chip">nuclei</li>
          </ul>
        </article>
        <article class="skill-row">
          <div class="skill-info">
            <h3 class="skill-name">service-discovery <span class="risk risk-active">active</span></h3>
            <p class="skill-desc">TCP service and version discovery on the top 1000 ports.</p>
          </div>
          <ul class="chips" aria-label="Tools">
            <li class="chip">nmap</li>
          </ul>
        </article>
      </div>
      <p class="section-note"><a href="${url("/docs/scan-skills/")}">Read how the safety model works →</a></p>
    </div>
  </section>

  <section class="section closing">
    <div class="wrap closing-inner">
      <p class="kicker">Get started</p>
      <h2 class="section-title">Scope in. Report out.</h2>
      <p class="section-lede">Install the CLI, run the wizard, point it at an authorized target.</p>
      <div class="cta-row">
        <a class="btn btn-primary" href="${url("/docs/getting-started/")}">Read the docs</a>
        <a class="btn btn-ghost" href="${SITE.repoUrl}">View source</a>
      </div>
      <p class="install-line"><span class="install-prompt">$</span> npm i -g opensecuritybot</p>
      <p class="section-note">Node 20+ · ${SITE.license} · one runtime dependency (commander)</p>
    </div>
  </section>
`;
}
