# Releasing opensecuritybot

Published to the public npm registry as `opensecuritybot` (bin: `vapt`).

## 1. Bump the version in both places

`package.json` and `src/version.ts` must match — a test fails if they drift.

```sh
npm version minor --no-git-tag-version   # or patch / major
```

Then edit `src/version.ts` by hand:

```ts
export const VERSION = "0.6.0";
```

Also update the static version badge near the top of `README.md`
(`img.shields.io/badge/version-x.y.z-blue`).

## 2. Build and test

```sh
npm run build && npm test
```

Must be green (~72 tests).

## 3. Inspect the tarball

```sh
npm pack --dry-run
```

Confirm `dist/`, `skills/`, `README.md` and `LICENSE` are in, and nothing stray
(no `src/`, `test/`, `examples/`) sneaks in.

## 4. Tag, release, let CI publish

```sh
git add -A && git commit -m "Release v0.6.0"
git push origin main
git tag v0.6.0 && git push origin v0.6.0
```

Then create a GitHub Release for the tag. That triggers
`.github/workflows/publish.yml`, which re-runs build + tests and publishes with
provenance.

One-time setup: on npmjs.com, `opensecuritybot` → Settings → Trusted Publisher →
GitHub Actions, owner `Aditya-Prakash14`, repository `opensecuritybot`, workflow
`publish.yml`. After that the workflow needs **no token** — npm verifies it via OIDC.

## 5. Manual publish (fallback)

```sh
npm login
npm publish --access public
```

`prepublishOnly` runs `npm run build && npm test`, so a failing test blocks the
publish. A manual publish cannot carry provenance (that is OIDC-only) and will
prompt for a 2FA one-time password — bypass-2FA tokens are being deprecated for
direct publishing, so expect the prompt. The same applies to `npm stage reject`
and `npm stage approve`.

## 6. Verify

```sh
npm view opensecuritybot version
npx opensecuritybot --version
npx opensecuritybot skills
```

## Notes

- A published version cannot be unpublished after 72 hours — if it is broken,
  publish a patch instead of trying to delete it.
- Common failures:
  - `E401` / `ENEEDAUTH` — expired or missing token.
  - `EOTP` — npm wants a 2FA one-time password; run `npm login`.
  - `E409` — that version already exists; bump the version.
