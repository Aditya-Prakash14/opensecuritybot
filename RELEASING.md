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

## 5. Manual publish (fallback)

```sh
npm login                 # or: export NPM_TOKEN=...
npm publish --access public --provenance
```

`prepublishOnly` runs `npm run build && npm test`, so a failing test blocks the
publish.

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
