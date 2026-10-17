#!/usr/bin/env node
/**
 * Static build for the opensecuritybot docs site.
 *
 * Renders the landing page, one page per DOCS entry (content/<slug>.md, with
 * the root SECURITY.md / CHANGELOG.md fallbacks), a 404 page, and copies the
 * static assets into apps/docs/dist. Zero dependencies, deterministic output,
 * no minification and no hashing.
 *
 * Usage: node apps/docs/build.mjs            (SITE_BASE for project-page deploys)
 */

import { existsSync } from "node:fs";
import { copyFile, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { DOCS, SITE, landing, layout, url } from "./src/layout.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const CONTENT_DIR = join(HERE, "content");
const PUBLIC_DIR = join(HERE, "public");
const SRC_DIR = join(HERE, "src");
const DIST = join(HERE, "dist");

// Fail loudly if layout.mjs stops exporting what this build imports.
for (const [name, value] of Object.entries({ layout, landing, DOCS, url, SITE })) {
  if (value === undefined) throw new Error(`apps/docs/src/layout.mjs must export ${name}`);
}

/* --- markdown ------------------------------------------------------------- */

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (value) => String(value).replace(/[&<>"']/g, (char) => ESCAPES[char]);

/** Only relative, anchor, http(s) and mailto hrefs survive. */
const isSafeHref = (href) => !/^[a-z][a-z0-9+.-]*:/i.test(href) || /^(https?|mailto):/i.test(href);

/** Inline markdown: code spans first, then strong/em/links on the plain runs. */
function inline(text) {
  return String(text)
    .split(/(`[^`]*`)/)
    .map((part) => {
      if (part.startsWith("`")) return `<code>${esc(part.slice(1, -1))}</code>`;
      return esc(part)
        .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
        .replace(/\*([^*]+)\*/g, "<em>$1</em>")
        .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (all, label, href) =>
          isSafeHref(href) ? `<a href="${href}">${label}</a>` : all
        );
    })
    .join("");
}

/** GitHub-style id: lowercase, punctuation dropped, spaces to hyphens. */
const slugify = (text) =>
  String(text)
    .toLowerCase()
    .replace(/<[^>]*>/g, "")
    .replace(/[^\p{L}\p{N} _-]/gu, "")
    .trim()
    .replace(/[ \t]/g, "-");

const plainHeading = (text) =>
  String(text)
    .replace(/`([^`]*)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[*_]{1,2}/g, "")
    .trim();

/** Render the supported markdown subset to HTML and collect the h2/h3 toc. */
export function renderMarkdown(markdown) {
  const lines = String(markdown).replace(/\r\n?/g, "\n").split("\n");
  const out = [];
  const toc = [];
  const seen = new Map();
  const uniqueId = (base) => {
    if (!seen.has(base)) {
      seen.set(base, 0);
      return base;
    }
    const next = seen.get(base) + 1;
    seen.set(base, next);
    return `${base}-${next}`;
  };

  const cells = (line) =>
    line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
  const isSeparator = (line) => {
    if (!line || !line.includes("|")) return false;
    const row = cells(line);
    return row.length > 0 && row.every((cell) => /^:?-{2,}:?$/.test(cell));
  };
  const itemMatch = (line) => /^(\s*)(?:[-*+]|(\d+)\.)\s+(.*)$/.exec(line);

  const renderList = (top) => {
    const tag = top[0].ordered ? "ol" : "ul";
    const lis = top.map((item) => {
      const nested = item.children.length ? `\n${renderList(item.children)}` : "";
      return `<li>${inline(item.text)}${nested}</li>`;
    });
    return `<${tag}>\n${lis.join("\n")}\n</${tag}>`;
  };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    if (!line.trim()) {
      i += 1;
      continue;
    }

    const fence = /^```\s*([A-Za-z0-9+#.-]*)\s*$/.exec(line);
    if (fence) {
      const code = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) code.push(lines[i++]);
      i += 1; // closing fence, or EOF
      const cls = fence[1] ? ` class="language-${esc(fence[1])}"` : "";
      out.push(`<pre><code${cls}>${esc(code.join("\n"))}\n</code></pre>`);
      continue;
    }

    const heading = /^(#{1,3})\s+(.+?)\s*#*\s*$/.exec(line);
    if (heading) {
      // The article already renders one h1; a markdown h1 becomes an h2 section.
      const level = Math.max(2, heading[1].length);
      const text = plainHeading(heading[2]);
      const id = uniqueId(slugify(text) || "section");
      toc.push({ id, text, level });
      out.push(`<h${level} id="${esc(id)}">${inline(heading[2])}</h${level}>`);
      i += 1;
      continue;
    }

    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      out.push("<hr />");
      i += 1;
      continue;
    }

    if (/^>\s?/.test(line)) {
      const quote = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) quote.push(lines[i++].replace(/^>\s?/, ""));
      out.push(`<blockquote><p>${inline(quote.join(" "))}</p></blockquote>`);
      continue;
    }

    if (line.includes("|") && i + 1 < lines.length && isSeparator(lines[i + 1])) {
      const header = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim() && lines[i].includes("|")) rows.push(cells(lines[i++]));
      const head = header.map((cell) => `<th>${inline(cell)}</th>`).join("");
      const body = rows
        .map((row) => {
          const pads = Array.from({ length: header.length }, (_, c) => row[c] ?? "");
          return `<tr>${pads.map((cell) => `<td>${inline(cell)}</td>`).join("")}</tr>`;
        })
        .join("\n");
      out.push(`<table>\n<thead>\n<tr>${head}</tr>\n</thead>\n<tbody>\n${body}\n</tbody>\n</table>`);
      continue;
    }

    if (itemMatch(line)) {
      const items = [];
      while (i < lines.length) {
        const match = itemMatch(lines[i]);
        if (match) {
          items.push({ indent: match[1].length, ordered: Boolean(match[2]), text: match[3], children: [] });
          i += 1;
          continue;
        }
        if (!lines[i].trim()) {
          // Keep the list open across a blank line only when the same list resumes.
          const next = lines[i + 1];
          const nextItem = next ? itemMatch(next) : null;
          const sameList = nextItem ? Boolean(nextItem[2]) === items[0].ordered : /^\s{2,}\S/.test(next ?? "");
          if (sameList) {
            i += 1;
            continue;
          }
          break;
        }
        if (/^(#{1,6}\s|```|>)/.test(lines[i])) break;
        items[items.length - 1].text += ` ${lines[i].trim()}`; // lazy continuation line
        i += 1;
      }
      const base = Math.min(...items.map((item) => item.indent));
      const top = [];
      for (const item of items) {
        if (item.indent > base && top.length) top[top.length - 1].children.push(item);
        else top.push(item);
      }
      out.push(renderList(top));
      continue;
    }

    const paragraph = [line];
    i += 1;
    while (i < lines.length && lines[i].trim()) {
      const next = lines[i];
      const startsBlock =
        /^#{1,6}\s/.test(next) ||
        /^```/.test(next) ||
        /^>\s?/.test(next) ||
        /^\s*(?:[-*+]|\d+\.)\s+/.test(next) ||
        /^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(next) ||
        (next.includes("|") && i + 1 < lines.length && isSeparator(lines[i + 1]));
      if (startsBlock) break;
      paragraph.push(next);
      i += 1;
    }
    out.push(`<p>${inline(paragraph.join(" "))}</p>`);
  }

  return { html: out.join("\n"), toc };
}

/* --- content -------------------------------------------------------------- */

/** Root-file fallbacks; every other slug must live in content/. */
const ROOT_FALLBACKS = { security: "SECURITY.md", changelog: "CHANGELOG.md" };

function resolveContent(slug) {
  const local = join(CONTENT_DIR, `${slug}.md`);
  if (existsSync(local)) return local;
  const fallback = ROOT_FALLBACKS[slug] ? join(REPO_ROOT, ROOT_FALLBACKS[slug]) : null;
  if (fallback && existsSync(fallback)) return fallback;
  throw new Error(`missing content for docs slug "${slug}": expected ${local}${fallback ? ` or ${fallback}` : ""}`);
}

/** Strip YAML frontmatter. Title/description only; anything else is an error. */
function stripFrontmatter(raw, source) {
  if (!raw.startsWith("---\n") && !raw.startsWith("---\r\n")) return { meta: {}, body: raw };
  const match = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(raw);
  if (!match) throw new Error(`unsupported frontmatter in ${source}: missing closing ---`);
  const meta = {};
  for (const line of match[1].split(/\r?\n/)) {
    if (!line.trim()) continue;
    const entry = /^([A-Za-z][A-Za-z0-9_-]*):(\s+.*|\s*)$/.exec(line);
    if (!entry) throw new Error(`unsupported frontmatter in ${source}: ${JSON.stringify(line)}`);
    let value = entry[2].trim();
    if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
      value = value.slice(1, -1);
    }
    meta[entry[1]] = value;
  }
  return { meta, body: raw.slice(match[0].length) };
}

/** Drop markdown reference definitions (e.g. CHANGELOG link footers) the minimal renderer cannot use. */
function stripRefDefinitions(body) {
  return body
    .split(/\r?\n/)
    .filter((line) => !/^\[[^\]]+\]:\s+\S+/.test(line))
    .join("\n");
}

/* --- build ---------------------------------------------------------------- */

async function copyDir(from, to) {
  const entries = await readdir(from, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const src = join(from, entry.name);
    const dest = join(to, entry.name);
    if (entry.isDirectory()) {
      await mkdir(dest, { recursive: true });
      await copyDir(src, dest);
    } else if (entry.isFile()) {
      await copyFile(src, dest);
    }
  }
}

async function build() {
  await rm(DIST, { recursive: true, force: true });
  await mkdir(join(DIST, "assets"), { recursive: true });

  const routes = [];
  const write = async (route, file, html) => {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, html);
    routes.push(route);
    console.log(`  ${route}`);
  };

  await write(
    "/",
    join(DIST, "index.html"),
    layout({ title: null, description: SITE.description, path: "/", body: landing() })
  );

  for (const [index, doc] of DOCS.entries()) {
    const source = resolveContent(doc.slug);
    const { meta, body } = stripFrontmatter(await readFile(source, "utf8"), source);
    const cleanBody = stripRefDefinitions(body);
    const { html, toc } = renderMarkdown(cleanBody);
    await write(
      `/docs/${doc.slug}/`,
      join(DIST, "docs", doc.slug, "index.html"),
      layout({
        title: doc.title || meta.title,
        description: doc.description || meta.description || SITE.description,
        path: `/docs/${doc.slug}/`,
        body: html,
        toc,
        prev: DOCS[index - 1] ?? null,
        next: DOCS[index + 1] ?? null,
      })
    );
  }

  await writeFile(
    join(DIST, "404.html"),
    layout({
      title: "Page not found",
      description: `That page does not exist. ${SITE.description}`,
      path: "/404/",
      body: `      <p>The page you asked for does not exist.</p>
      <p><a href="${url("/")}">Home</a> · <a href="${url("/docs/getting-started/")}">Documentation</a></p>`,
    })
  );

  await copyFile(join(SRC_DIR, "theme.css"), join(DIST, "assets", "theme.css"));
  await copyFile(join(SRC_DIR, "app.js"), join(DIST, "assets", "app.js"));
  if (existsSync(PUBLIC_DIR)) await copyDir(PUBLIC_DIR, DIST);
  await writeFile(join(DIST, ".nojekyll"), "");

  console.log(`built ${routes.length} routes into ${DIST}`);
}

await build();
