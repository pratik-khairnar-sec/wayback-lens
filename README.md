# Wayback Lens

Landing page: enable GitHub Pages (Settings, Pages, branch `main`, folder `/docs`) to publish `docs/index.html`.

A Chrome extension for recon. It pulls every URL the Internet Archive has ever captured for a target, then lets you triage them in a proper workspace instead of a wall of raw text.

![Popup](docs/popup.png)

![Results workspace](docs/results.png)

*Screenshots use sample data for `example.com`.*

## What it does

Pick a target (it pre-fills from the active tab) and choose a scan:

| Scan | What it finds | CDX request |
|---|---|---|
| Main domain | Every archived path on the exact host | `url=host/*` |
| All subdomains | The host and every subdomain beneath it | `url=domain&matchType=domain` |
| This path | Everything under the current path | `url=origin/path&matchType=prefix` |
| Sensitive files | Backups, dumps, keys, configs, logs, documents | `matchType=domain` + extension filter |
| JavaScript | `.js` / `.mjs` bundles for endpoint and secret hunting | `matchType=domain` + `.js` filter |
| With parameters | Query-string URLs to feed into fuzzers | `matchType=domain` + `?...=` filter |

Hover or focus any scan and the popup shows the exact request it will send.

### Results workspace

- Streams results with live progress, a cancel button and a timeout, so large targets do not freeze the browser.
- Ranks every URL by risk (keys, `.env`, `.git`, SQL dumps and `.bak` files first) and classifies it by file type.
- Filters by file type, host, parameters, and free text or regular expression.
- Opens the archived snapshot for any row, or copies the URL.
- Exports the current view as TXT, CSV or JSON, or exports just the unique hosts (a quick passive subdomain list).
- **Status filter:** split results into Found (200), Redirects, Not found (404) and errors, or tick "Only 200" to hide dead captures instantly.
- **Verify live (optional):** sends HEAD requests to check which URLs respond right now, and shows a `live 200` badge on each row. Checks the highest-risk URLs in the current view first, up to 500 per run. The browser asks for host permission only when you click it.
- Clear errors for rate limiting, timeouts and empty results, with a retry button.

## Install

1. Clone or download this repository:
   ```bash
   git clone https://github.com/pratik-khairnar-sec/wayback-lens.git
   ```
2. Open `chrome://extensions` and enable **Developer mode**.
3. Click **Load unpacked** and select the project folder.
4. Pin the extension, open a target site, and click the icon.

Works in Chrome and other Chromium browsers (Edge, Brave) that support Manifest V3.

## Privacy and permissions

| Permission | Why |
|---|---|
| `activeTab` | Read the current tab's URL to pre-fill the target, only when you open the popup |
| `storage` | Remember your last options and five recent targets, locally |
| `https://web.archive.org/*` | Query the public CDX API from the results page |
| Optional: all `http(s)` sites | Requested only when you click **Verify live**, so the extension can read live status codes. Revoke it anytime from `chrome://extensions` |

No analytics, no accounts, no third-party servers, and no remote code or fonts. Archived URLs are attacker-controlled data, so they are always rendered as text and never as HTML.

## Responsible use

Archive data is public, but what you do with it is not automatically authorized. Only probe live hosts that are in scope for a bug bounty program or that you have written permission to test. The "open live URL" button exists for that purpose.

## Limits worth knowing

- **Archived status is not live status.** A 404 means that capture was a 404; the page may work today (or the reverse). Use Verify live to check, and remember WAFs and CDNs can answer HEAD requests differently.
- The CDX API collapses captures by URL, so the archived status is that of the first capture. The popup's "Archived 200 only" option asks the archive for URLs that have at least one 200 capture, which is more thorough than the instant client-side filter.
- Very large domains can exceed the result cap. Use a narrower scan, the 200-only filter, or raise the limit.
- The Wayback Machine rate-limits heavy use.

## Project layout

```
manifest.json     MV3 manifest
popup.html        Scan launcher
results.html      Results workspace
src/core.js       Query builder, parser, classifier, exports, icons
src/popup.*       Popup logic and styles
src/results.*     Results logic and styles
src/theme.css     Shared design tokens
icons/            Extension icons
```

## Changelog

**1.0.0**
- Six scans: main domain, all subdomains, path, sensitive files, JavaScript and parameterised URLs.
- Results workspace with risk ranking, file-type, host and status filters, text and regex search.
- Archived snapshot links and TXT, CSV, JSON and hosts export.
- Optional live verification with a "Live now only" filter.
- Fully offline UI: no CDN fonts or icon libraries, strict extension CSP.

## Author and license

Built and maintained by [Pratik Khairnar](https://github.com/pratik-khairnar-sec).

Released under the [MIT License](LICENSE).

Wayback Machine and Internet Archive are trademarks of the Internet Archive. This project is not affiliated with or endorsed by them.
