# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-05

### Initial Stable Release — Recon & Triage Workspace

Major initial release introducing the Manifest V3 Chrome Extension and interactive triage workspace for high-velocity passive recon using the Wayback Machine CDX API.

### Added
- **Six Targeted Scan Profiles**:
  - `Main domain` (`url=host/*`): Captures all archived endpoints under the exact host.
  - `All subdomains` (`matchType=domain`): Passive subdomain discovery covering the target root and all sub-hosts.
  - `This path` (`matchType=prefix`): Scopes archived discovery beneath the active directory/path.
  - `Sensitive files`: Targets database dumps, backups, `.env` configs, private keys, and logs.
  - `JavaScript`: Locates historical `.js` and `.mjs` bundles for endpoint and secret hunting.
  - `With parameters`: Isolates URLs with query strings formatted for fuzzing, SSRF, and IDOR testing.
- **Non-Blocking Streaming CDX Engine**:
  - Incremental chunk parsing via `ReadableStream` and `TextDecoder` to handle 100,000+ records smoothly without freezing browser threads or exhausting memory.
- **Autonomous Risk Scoring Engine**:
  - **Risk 3 (High)**: Leaked credentials (`.env`, `.pem`, `.key`, `id_rsa`), database dumps (`.sql`, `.sqlite`, `.db`), source trees (`.git`), backups (`.bak`, `.swp`), and `.htpasswd`.
  - **Risk 2 (Medium)**: Server configs (`.yml`, `.conf`, `.ini`), logs (`.log`), and JavaScript source maps (`.map`).
  - **Risk 1 (Low)**: JavaScript files, documents (`.pdf`, `.xlsx`, `.docx`), and binaries.
- **Live HTTP 200 Verification**:
  - User-consented multi-worker prober sending asynchronous HEAD requests to verify which historical endpoints are actively responding on live targets today.
- **Interactive Results Workspace**:
  - Faceted filters for file types, response statuses (200, 3xx, 404, 4xx, 5xx), and discovered subdomains.
  - Case-insensitive search and arbitrary Regular Expression (`.*`) matching.
  - Dedicated "Reset Filters" action and instant filter clearing.
  - Keyboard shortcuts (<kbd>/</kbd> to search, <kbd>Esc</kbd> to clear).
  - Snapshot integration: direct links to Wayback Machine archived snapshots.
- **Universal Export Engine**:
  - One-click downloads for `TXT`, `CSV`, `JSON`, and passive subdomain `Hosts` list.
  - Clipboard copy button for current filtered views.
- **Community & Automation Infrastructure**:
  - Automated GitHub Pages deployment workflow (`pages.yml`).
  - Automated Release packager workflow (`release.yml`).
  - Automated syntax and manifest CI validator (`ci.yml`).
  - Interactive product showcase and live simulator on GitHub Pages (`docs/index.html`).

### Security & Privacy
- Zero tracking, zero telemetry, and zero third-party dependencies.
- Strict Manifest V3 Content Security Policy (CSP).
- Untrusted archive inputs treated strictly as text nodes to guarantee XSS prevention.
