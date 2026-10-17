#!/usr/bin/env node
/**
 * Dev/preview server for the built docs site.
 *
 * Builds first (importing build.mjs), then serves apps/docs/dist on
 * 127.0.0.1:PORT (default 4321). Zero dependencies. Static paths only: no
 * path traversal, no query handling, no directory listing.
 *
 * Usage: node apps/docs/serve.mjs            (PORT=4321 by default)
 */

import { createReadStream, existsSync } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import "./build.mjs";

const DIST = join(dirname(fileURLToPath(import.meta.url)), "dist");
const DIST_ROOT = resolve(DIST);
const PORT = Number(process.env.PORT ?? 4321);
const HOST = "127.0.0.1";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".png": "image/png",
  ".woff2": "font/woff2",
};

const contentType = (file) => MIME[extname(file).toLowerCase()] ?? "application/octet-stream";

const isFile = async (file) => {
  const info = await stat(file).catch(() => null);
  return Boolean(info?.isFile());
};

createServer(async (req, res) => {
  let requested = (req.url || "/").split(/[?#]/)[0];
  let pathname;
  try {
    pathname = decodeURIComponent(requested);
  } catch {
    res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
    res.end("bad request\n");
    console.log(`400 ${requested}`);
    return;
  }
  if (pathname.includes("..") || pathname.includes("\0")) {
    res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
    res.end("bad request\n");
    console.log(`400 ${requested}`);
    return;
  }

  if (!pathname.startsWith("/")) pathname = `/${pathname}`;
  let target = resolve(join(DIST, pathname));
  if (target !== DIST_ROOT && !target.startsWith(DIST_ROOT + sep)) {
    res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
    res.end("bad request\n");
    console.log(`400 ${requested}`);
    return;
  }

  const redirect = (location) => {
    res.writeHead(301, { location });
    res.end();
    console.log(`301 ${requested} -> ${location}`);
  };

  let info = await stat(target).catch(() => null);
  if (info?.isDirectory()) {
    if (!pathname.endsWith("/")) {
      redirect(`${pathname}/`);
      return;
    }
    target = join(target, "index.html");
    info = await stat(target).catch(() => null);
  } else if (!info && !pathname.endsWith("/") && (await isFile(join(target, "index.html")))) {
    redirect(`${pathname}/`);
    return;
  }

  if (!info?.isFile()) {
    const page = join(DIST, "404.html");
    if (existsSync(page)) {
      res.writeHead(404, { "content-type": MIME[".html"] });
      createReadStream(page).pipe(res);
    } else {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("not found\n");
    }
    console.log(`404 ${requested}`);
    return;
  }

  res.writeHead(200, { "content-type": contentType(target) });
  createReadStream(target).pipe(res);
  console.log(`200 ${requested}`);
}).listen(PORT, HOST, () => {
  console.log(`serving ${DIST} on http://${HOST}:${PORT}`);
});
