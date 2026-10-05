# Security Policy

## Supported Versions

Only the latest release of Wayback Lens is officially supported with security updates and patches.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of **Wayback Lens** and its users seriously. If you believe you have discovered a security vulnerability, please report it responsibly:

1. **Do not create a public GitHub issue.**
2. Send an email or private security advisory through GitHub:
   - Go to the [Security Tab](https://github.com/pratik-khairnar-sec/wayback-lens/security/advisories) of the repository.
   - Click **Report a vulnerability** to open a private draft report.
   - Alternatively, contact **Pratik Khairnar** directly via GitHub: [@pratik-khairnar-sec](https://github.com/pratik-khairnar-sec).
3. Include the following details in your report:
   - Detailed description of the vulnerability.
   - Proof of Concept (PoC) or reproducible steps.
   - Expected impact and severity assessment.
   - Any suggested remediations or mitigations.

### Response Timeline
- **Initial Acknowledgement**: Within 48 hours.
- **Triage & Assessment**: Within 5 business days.
- **Remediation & Patch Release**: Coordinated with the reporter before public disclosure.

---

## Security Architecture & Design Principles

Wayback Lens was engineered with defense-in-depth principles:

1. **Manifest V3 Content Security Policy (CSP)**:
   - Extension pages enforce `script-src 'self'; object-src 'self'; base-uri 'none'; frame-ancestors 'none'`.
   - Execution of arbitrary remote scripts, `eval()`, or untrusted inline JS is strictly blocked by the browser.
2. **Untrusted Data Sanitization**:
   - Archived URLs retrieved from the Internet Archive CDX API are attacker-controlled data.
   - All URLs, paths, query strings, and parameters are rendered into the DOM exclusively as text nodes (`textContent`, `append(text)`) — never injected via `innerHTML`.
3. **Zero Telemetry / Offline UI**:
   - The extension contains zero tracking scripts, analytics libraries, or external telemetry beacons.
   - All UI icons are packaged as an inline SVG sprite system.
4. **Scoped Permissions**:
   - `activeTab`: Scoped exclusively to reading the target host upon user popup launch.
   - `storage`: Preserves user preferences locally using `chrome.storage.local`.
   - Cross-origin HTTP/HTTPS permissions for the live prober are marked `optional` and requested on-demand only when explicitly triggered by the user.
