/**
 * Page chrome for the opensecuritybot docs site.
 *
 * Owns: document head, header/footer, the docs shell (sidebar + article +
 * "On this page" rail) and the page-title rules. Content comes from build.mjs;
 * this module owns every wrapper, link and escaping decision.
 */

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ESCAPES[char]);

/** Deploy base path, e.g. SITE_BASE=/opensecuritybot for GitHub project pages. */
export const BASE = process.env.SITE_BASE ?? "";

/** Absolute origin for social previews, e.g. SITE_ORIGIN=https://example.github.io. */
export const ORIGIN = process.env.SITE_ORIGIN ?? "";

/** Join the deploy base with an absolute site path: "/docs/x/" -> "<base>/docs/x/". */
export function url(p = "/") {
  const base = BASE.replace(/\/+$/, "");
  const path = String(p).startsWith("/") ? String(p) : `/${p}`;
  return `${base}${path}`;
}

export const SITE = {
  name: "opensecuritybot",
  command: "vapt",
  version: "0.5.2",
  tagline: "The reasoning layer between your scanner and your report.",
  description:
    "Local Node.js CLI that triages, verifies and reports scanner findings for authorized VAPT engagements — scope-safe by construction, with any OpenAI-compatible or Anthropic provider.",
  repoUrl: "https://github.com/Aditya-Prakash14/opensecuritybot",
  npmUrl: "https://www.npmjs.com/package/opensecuritybot",
  license: "MIT",
};

export const DOCS = [
  { slug: "getting-started", title: "Getting started", section: "Start", description: "Install, configure and run your first engagement." },
  { slug: "scan-skills", title: "Scan skills", section: "Guides", description: "Run reviewed, scope-pinned scanner playbooks." },
  { slug: "verification", title: "Verification", section: "Guides", description: "How triage output is checked before you trust it." },
  { slug: "reports", title: "Reports", section: "Guides", description: "From findings to a client-ready VAPT report." },
  { slug: "cli-reference", title: "CLI reference", section: "Reference", description: "Every command, flag and environment variable." },
  { slug: "agent-integration", title: "Agent integration", section: "Reference", description: "Drive vapt from coding agents; AG-UI and MCP roadmap." },
  { slug: "security", title: "Security", section: "Project", description: "Threat model, disclosure policy and hard boundaries." },
  { slug: "changelog", title: "Changelog", section: "Project", description: "Release history." },
];

const HOME_TITLE = "opensecuritybot — scope-safe security reasoning";

const SHIELD_MARK = `<svg class="brand-mark" viewBox="0 0 32 32" width="22" height="22" aria-hidden="true" focusable="false"><path d="M16 3.6 5.4 7.9v7.7c0 5.7 4.3 10.1 10.6 12.8 6.3-2.7 10.6-7.1 10.6-12.8V7.9Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="m12.4 12.7 3.3 3.1-3.3 3.1" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M16.9 18.9h3.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`;

const docHref = (slug) => url(`/docs/${slug}/`);

/** Normalize a path for active-state comparison: strips BASE, keeps one trailing slash. */
function pathKey(p) {
  let s = String(p || "/");
  const base = BASE.replace(/\/+$/, "");
  if (base && (s === base || s.startsWith(`${base}/`))) s = s.slice(base.length);
  if (!s.startsWith("/")) s = `/${s}`;
  if (s.length > 1) s = `${s.replace(/\/+$/, "")}/`;
  return s;
}

const findDoc = (key) => DOCS.find((doc) => pathKey(docHref(doc.slug)) === key) ?? null;

/** Accept a DOCS entry, a bare slug, or an absolute site path. */
function docRef(item) {
  if (!item) return null;
  if (typeof item === "string") {
    const href = item.startsWith("/") ? url(item) : docHref(item);
    return { href, title: item };
  }
  const href = typeof item.href === "string" ? url(item.href) : docHref(String(item.slug ?? ""));
  return { href, title: String(item.title ?? item.slug ?? "") };
}

function header() {
  return `  <header class="site-header">
    <div class="header-inner">
      <a class="brand" href="${url("/")}">${SHIELD_MARK}<span class="brand-text">${esc(SITE.name)}</span></a>
      <span class="version-badge">v${esc(SITE.version)}</span>
      <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-nav">
        <span class="nav-toggle-icon" aria-hidden="true"></span>
        <span class="nav-toggle-label">Menu</span>
      </button>
      <nav id="site-nav" class="site-nav" aria-label="Primary">
        <a class="nav-link" href="${docHref("getting-started")}">Docs</a>
        <a class="nav-link" href="${SITE.repoUrl}">GitHub</a>
        <a class="nav-link" href="${SITE.npmUrl}">npm</a>
      </nav>
    </div>
  </header>`;
}

function footer() {
  return `  <footer class="site-footer">
    <div class="footer-inner">
      <p class="footer-meta">${esc(SITE.license)} · built for authorized engagements</p>
      <nav class="footer-links" aria-label="Footer">
        <a href="${SITE.npmUrl}">npm</a><span class="footer-sep" aria-hidden="true">·</span>
        <a href="${SITE.repoUrl}">GitHub</a><span class="footer-sep" aria-hidden="true">·</span>
        <a href="${docHref("getting-started")}">docs</a>
      </nav>
    </div>
  </footer>`;
}

function sidebar(activeKey) {
  const groups = new Map();
  for (const doc of DOCS) {
    if (!groups.has(doc.section)) groups.set(doc.section, []);
    groups.get(doc.section).push(doc);
  }

  const groupHtml = [...groups.entries()]
    .map(([section, docs]) => {
      const items = docs
        .map((doc) => {
          const isActive = pathKey(docHref(doc.slug)) === activeKey;
          const current = isActive ? ' aria-current="page"' : "";
          return `          <li><a class="side-link${isActive ? " is-active" : ""}" href="${docHref(doc.slug)}"${current}>${esc(doc.title)}</a></li>`;
        })
        .join("\n");
      return `      <div class="nav-group">
        <p class="nav-group-title">${esc(section)}</p>
        <ul class="nav-list">
${items}
        </ul>
      </div>`;
    })
    .join("\n");

  return `    <details class="sidebar" open>
      <summary class="sidebar-summary">Documentation</summary>
      <nav class="sidebar-nav" aria-label="Docs">
${groupHtml}
      </nav>
    </details>`;
}

function tocRail(toc) {
  const items = (toc ?? []).filter((entry) => entry && entry.id && entry.text);
  if (!items.length) return "";
  const list = items
    .map((entry) => {
      const level = Math.min(4, Math.max(2, Number(entry.level) || 2));
      return `        <li class="toc-item toc-level-${level}"><a href="#${esc(entry.id)}">${esc(entry.text)}</a></li>`;
    })
    .join("\n");
  return `    <aside class="toc-rail">
      <nav class="toc" aria-label="On this page">
        <p class="toc-title">On this page</p>
        <ul class="toc-list">
${list}
        </ul>
      </nav>
    </aside>`;
}

function pager(prev, next) {
  const p = docRef(prev);
  const n = docRef(next);
  if (!p && !n) return "";
  const parts = [];
  if (p) {
    parts.push(`        <a class="pager-link pager-prev" href="${p.href}"><span class="pager-label">← Previous</span><span class="pager-title">${esc(p.title)}</span></a>`);
  }
  if (n) {
    parts.push(`        <a class="pager-link pager-next" href="${n.href}"><span class="pager-label">Next →</span><span class="pager-title">${esc(n.title)}</span></a>`);
  }
  return `      <nav class="pager" aria-label="Pagination">
${parts.join("\n")}
      </nav>`;
}

function article({ title, body, prev, next, activeKey }) {
  const doc = findDoc(activeKey);
  const section = doc ? `          <li>${esc(doc.section)}</li>\n` : "";
  return `    <article class="doc">
      <nav class="breadcrumb" aria-label="Breadcrumb">
        <ol class="breadcrumb-list">
          <li><a href="${url("/")}">Home</a></li>
${section}          <li aria-current="page">${esc(title)}</li>
        </ol>
      </nav>
      <h1 class="doc-title">${esc(title)}</h1>
      <div class="prose">
${body}
      </div>
${pager(prev, next)}
    </article>`;
}

function docsShell({ title, body, toc, prev, next, activeKey }) {
  const rail = tocRail(toc);
  return `  <div class="docs-shell${rail ? "" : " no-toc"}">
${sidebar(activeKey)}
${article({ title, body, prev, next, activeKey })}
${rail}
  </div>`;
}

/** Home bodies may arrive wrapped in <main>; unwrap so <main id="main"> stays unique. */
function unwrapMain(html) {
  const match = /^\s*<main\b[^>]*>([\s\S]*)<\/main>\s*$/.exec(String(html));
  return match ? match[1] : String(html);
}

/** Full HTML document for any page. path "/" renders body directly in <main>. */
export function layout({ title = "", description = "", path = "/", body = "", toc = [], prev = null, next = null } = {}) {
  const key = pathKey(path);
  const home = key === "/";
  const heading = home ? HOME_TITLE : `${title || SITE.name} — ${SITE.name}`;
  const metaDescription = description || SITE.description;
  const content = home ? unwrapMain(body) : docsShell({ title: title || SITE.name, body, toc, prev, next, activeKey: key });

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="${esc(metaDescription)}" />
  <meta name="theme-color" content="#070906" />
  <meta name="color-scheme" content="dark" />
  <meta property="og:type" content="website" />
  <meta property="og:title" content="${esc(heading)}" />
  <meta property="og:description" content="${esc(metaDescription)}" />
  <meta property="og:image" content="${ORIGIN}${url("/og.svg")}" />
  <meta name="twitter:card" content="summary_large_image" />
  <link rel="icon" href="${url("/favicon.svg")}" type="image/svg+xml" />
  <link rel="stylesheet" href="${url("/assets/theme.css")}" />
  <script defer src="${url("/assets/app.js")}"></script>
  <title>${esc(heading)}</title>
</head>
<body>
  <a class="skip-link" href="#main">Skip to content</a>
${header()}
  <main id="main">
${content}
  </main>
${footer()}
</body>
</html>
`;
}

// landing() lives in landing.mjs; re-exported so either import style works.
export { landing } from "./landing.mjs";
