# Secret Remover 🔍

[![Client-Side](https://img.shields.io/badge/Architecture-100%25%20Client--Side-brightgreen?style=for-the-badge)](https://secretremover.com)
[![Open Source](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Privacy-Zero%20Data%20Retention-orange?style=for-the-badge)](https://secretremover.com)

A fast, fully client-side web application designed to locally scan and remove hardcoded secrets (API keys, passwords, tokens) from your codebase before you share it, commit it, or analyze it with AI tools.

### 🌐 Live Demo: [secretremover.com](https://secretremover.com)

---

## Why Secret Remover?

As AI-assisted coding and automated code reviews become the norm, it's easier than ever to unintentionally leak hardcoded credentials to third-party services. **Secret Remover** solves this by letting you safely scrub your code completely offline in your browser. 

**Your code never leaves your computer.** Everything is processed locally via browser-based JavaScript using regex pattern matching and entropy analysis.

![Secret Remover Demo](demo.gif)

---

## 🚀 Features

- **100% Client-Side:** No backend, no servers, zero data retention. High security and privacy.
- **Drag & Drop UI:** Simply drop a `.zip` of your source code into the browser.
- **Comprehensive Scanning:** Detects 85+ distinct types of secrets (AWS keys, GitHub tokens, passwords, Slack webhooks, etc.) and uses Shannon entropy targeting for unknown high-entropy keys.
- **Selective Redaction:** Review all findings and choose exactly which secrets to redact or keep.
- **Custom Keywords:** Add specific keywords or Custom Regex (e.g. `password1|password2`) to re-scan locally.
- **Smart Remediation:** Downloads a perfectly sanitized identical `.zip` replica of your source code with all selected secrets replaced by safe redacted placeholders.
- **Export Reports:** Generate JSON or CSV reports documenting all discovered tokens for compliance or auditing.
- **Beautiful E-Ink Aesthetic:** Clean, minimalist UI designed for readability.

---

## 🛠️ Usage Example (Custom Keywords)

By default, the engine scans for generic high-impact secrets. You can easily add multiple custom regex patterns or keywords to the engine dynamically using the pipe `|` operator:

```regex
password1|password2|database_user_123|\b[A-Za-z0-9]{20,40}\b
```

---

## 💻 Local Development

If you prefer to run this tool locally instead of visiting the live site, simply clone the repository and serve the static files:

```bash
# Clone the repository
git clone https://github.com/your-username/secret-remover.git
cd secret-remover

# Start a local HTTP server
python3 -m http.server 8080

# Or using Node.js
npx serve .
```

Then visit `http://localhost:8080` in your web browser.

---

## 📁 Project Structure

```text
.
├── index.html      # Main application interface
├── 404.html        # Custom "Not Found" magnifier page
├── app.js          # Core scanning logic, UI state, and Zip generation
├── patterns.js     # Dictionary of 85+ Regular Expressions and Secrets
├── styles.css      # E-ink themed styling 
└── favicon.svg     # Clean magnifier icon
```

---

## 🛡️ License

This project is open-source and available under the [MIT License](LICENSE).
