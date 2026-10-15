# Contributing to opensecuritybot (VAPT-Agent)

Thank you for your interest in contributing to **opensecuritybot**!

## Development Setup

1. **Prerequisites**:
   - Node.js >= 20.0.0
   - npm >= 9.0.0

2. **Clone and Install**:
   ```sh
   git clone https://github.com/Aditya-Prakash14/opensecuritybot.git
   cd opensecuritybot
   npm install
   ```

3. **Running in Development**:
   ```sh
   npm run dev -- --help
   npm run dev -- triage -f examples/findings.json -s examples/scope.json -c examples/cve-cache
   ```

## Running Tests & Type-Checking

Before submitting a PR, ensure all tests and type checks pass:

```sh
npm test        # Runs core test suite with node:test
npm run build   # Type-checks with tsc
```

## Architecture & Code Principles

- **Zero-Dependency Philosophy**: Keep runtime dependencies minimal. Aside from `commander`, core features (ANSI formatting, HTTP streaming, IP parsing, markdown generation) use standard Node.js APIs.
- **Safety First**:
  - All scanner findings must pass through `scope-guard.ts` before reaching the LLM reasoning layer.
  - Never emit exploit payloads or credentials in triage/report outputs.
  - LLM inputs and CVE references must be validated by `verify.ts`.
- **Config & Secrets**:
  - Configuration files (`config.json`) must remain owner-read/write only (`0600`).
  - Never commit API keys or authorized engagement scope data to version control.

## Submitting Pull Requests

1. Create a feature branch from `main`:
   ```sh
   git checkout -b feature/my-new-feature
   ```
2. Commit with descriptive messages:
   ```sh
   git commit -m "feat(scope): add support for IPv6 CIDR masking"
   ```
3. Push to your fork and submit a PR against `main`. All CI checks (Node 20 & 22) must pass.
