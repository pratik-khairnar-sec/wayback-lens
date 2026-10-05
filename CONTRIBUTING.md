# Contributing to Wayback Lens

Thank you for your interest in contributing to **Wayback Lens**! We welcome community contributions, bug fixes, feature proposals, and documentation enhancements.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat all contributors with respect.

---

## How Can I Contribute?

### 1. Reporting Bugs
- Check the [Issues tracker](https://github.com/pratik-khairnar-sec/wayback-lens/issues) to ensure the bug has not already been reported.
- Open a new issue using the **Bug Report** template.
- Provide clear steps to reproduce, browser version (e.g. Chrome 124, Brave 1.65), target domain tested, and console error logs if available.

### 2. Suggesting Enhancements
- Feature requests and improvements are welcome!
- Open an issue using the **Feature Request** template.
- Explain the problem, proposed solution, and why it benefits reconnaissance / bug bounty workflows.

### 3. Submitting Pull Requests (PRs)
1. **Fork** the repository and create a new feature branch from `main`:
   ```bash
   git checkout -b feature/awesome-addition
   ```
2. **Make your changes**:
   - Maintain the clean, lightweight architecture.
   - Do NOT introduce external npm build dependencies or remote CDNs for runtime extension code.
   - Follow existing vanilla JS and CSS token conventions in `src/theme.css`.
3. **Verify syntax**:
   ```bash
   node --check src/core.js
   node --check src/popup.js
   node --check src/results.js
   ```
4. **Test locally in Chrome**:
   - Load the unpacked extension at `chrome://extensions`.
   - Test against multiple domains (small sites and targets with 50,000+ captures).
   - Test all 6 scan modes, filters, regex search, and exports (`TXT`, `CSV`, `JSON`, `Hosts`).
5. **Commit and Push**:
   - Use clear, descriptive commit messages (e.g., `feat: add export format`, `fix: handle edge case in URL parsing`).
   - Open a Pull Request targeting `main`.

---

## Architecture & Code Guidelines

- **Vanilla JS**: Keep code modular, standard ES6+, and fast.
- **Manifest V3 Compliance**: Respect background script limitations and strict CSP.
- **XSS Prevention**: Never assign untrusted CDX archive output to `innerHTML`. Use `textContent` or `document.createElement`.
- **CSS Design System**: Use design tokens from `src/theme.css` (`var(--panel)`, `var(--amber)`, `var(--red)`, `var(--mono)`, etc.).

---

## Author & Maintainer

Maintained by **[Pratik Khairnar](https://github.com/pratik-khairnar-sec)**.
