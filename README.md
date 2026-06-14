# VulnBank 🏦

> **A deliberately vulnerable PHP banking application for security training and LLM-powered scanner testing.**

VulnBank simulates a realistic online banking portal packed with **18+ intentional security vulnerabilities** covering all OWASP Top 10 categories — plus extras like command injection, XXE, path traversal, and unrestricted file upload.

Use it to:
- Practice ethical hacking in a safe local environment
- Test and benchmark LLM-based security code scanners
- Learn how each OWASP vulnerability looks in real PHP code

---

## ⚠️ Warning

**This application is intentionally insecure.** Never deploy it on a public server or expose it to an untrusted network. For local use only.

---

## Requirements

- PHP 8.0+ with `pdo_sqlite` and `curl` extensions (both included by default)
- No database setup needed — SQLite is used and auto-initialized on first run

```bash
brew install php   # macOS (Homebrew)
```

---

## Quick Start

```bash
git clone https://github.com/<your-username>/vuln-bank.git
cd vuln-bank
php -S localhost:8080
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

**Demo accounts:**

| Username | Password   | Role  | Balance    |
|----------|------------|-------|------------|
| admin    | admin123   | admin | $999,999   |
| alice    | password123| user  | $15,000    |
| bob      | letmein    | user  | $3,200     |
| charlie  | charlie1   | user  | $87,500    |

---

## Vulnerabilities

### OWASP Top 10

| ID | Name | Where | Example Attack |
|----|------|-------|---------------|
| A01 | Broken Access Control | `dashboard.php`, `admin.php`, `register.php` | `?id=1` to view admin account; cookie `admin_override=vulnbank_admin` |
| A02 | Cryptographic Failures | `db.php`, `index.php`, `.env`, `_footer.php` | Unsalted MD5 passwords; plaintext creds in base64 remember-me cookie |
| A03 | Injection (SQLi + XSS) | `index.php`, `search.php`, `transfer.php`, `profile.php` | Login: `admin' --`; Search UNION exfil; stored XSS in bio/messages |
| A04 | Insecure Design | `transfer.php`, `register.php` | Negative transfer amount steals money; no email verification |
| A05 | Security Misconfiguration | `phpinfo.php`, `.env`, `config.php`, `backup.sql`, `debug.php` | `/debug.php` dumps session + DB with no auth; `/backup.sql` web-accessible |
| A06 | Vulnerable Components | `_header.php` | jQuery 1.12.4 (CVE-2020-11022), Bootstrap 4.0.0-alpha.6 |
| A07 | Auth Failures | `index.php`, `reset.php`, `logout.php` | No brute-force lockout; session fixation; reset via guessable security question |
| A08 | Integrity Failures | `transfer.php`, `profile.php` | No CSRF token on transfer; `unserialize()` on user cookie |
| A09 | Logging Failures | Everywhere | Zero audit logging — logins, transfers, admin access all untracked |
| A10 | SSRF | `profile.php` | Avatar URL: `file:///etc/passwd` or `http://169.254.169.254/latest/meta-data/` |

### Additional Vulnerabilities

| Type | File | Example |
|------|------|---------|
| Command Injection | `ping.php` | `127.0.0.1; cat .env` |
| Path Traversal | `download.php` | `?file=....//....//etc/passwd` |
| Unrestricted File Upload | `upload.php` | Upload `shell.php` → execute at `/uploads/shell.php?cmd=id` |
| XXE | `export.php` | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` in import XML |
| Code Injection (eval) | `eval.php` | Template `{{system('id')}}` → RCE |
| Open Redirect | `redirect.php` | `?url=http://evil.com/fake-login` |
| Unauthenticated API + CORS `*` | `api.php` | `curl api.php?action=users` — all users + hashes, no auth |
| Exposed Config/Backup Files | `.env`, `backup.sql`, `config.php`, `*.php.bak` | Direct URL access leaks all credentials |
| Debug Endpoint | `debug.php` | Dumps `$_SESSION`, `$_ENV`, DB users, .env — no auth |

---

## File Structure

```
vuln-bank/
├── index.php          # Login (SQLi, no lockout)
├── register.php       # Registration (mass assignment, weak passwords)
├── dashboard.php      # Dashboard (IDOR on ?id=)
├── transfer.php       # Transfer (no CSRF, negative amounts, SQLi)
├── transactions.php   # History (IDOR on ?user_id=)
├── profile.php        # Profile (stored XSS, SSRF, unserialize)
├── admin.php          # Admin panel (cookie/URL bypass)
├── search.php         # Search (UNION SQLi)
├── reset.php          # Password reset (no email verify, answer in source)
├── ping.php           # Diagnostic (command injection)
├── download.php       # File download (path traversal)
├── upload.php         # Photo upload (unrestricted .php upload)
├── export.php         # XML export/import (XXE)
├── eval.php           # Statement template (code injection via eval)
├── redirect.php       # Link handler (open redirect)
├── api.php            # JSON API (no auth, CORS *, SQLi)
├── debug.php          # Debug endpoint (full env dump, no auth)
├── config.php         # Legacy config (credentials exposed)
├── phpinfo.php        # PHP info (security misconfig)
├── hints.php          # 💡 Full vulnerability guide with exploit payloads
├── .env               # Exposed secrets (web-accessible)
├── backup.sql         # DB dump in webroot
├── index.php.bak      # Backup source file
└── db.php             # DB init (MD5 passwords, hardcoded secrets)
```

---

## Hints Page

Visit [http://localhost:8080/hints.php](http://localhost:8080/hints.php) for a full guide listing every vulnerability, where to find it, how to exploit it, and what the impact is.

---

## Use with an LLM Security Scanner

This app is designed as a benchmark target for LLM-based static analysis (SAST) tools. Feed any source file (or the whole repo) to your scanner and verify it catches:

- SQL injection in string-concatenated queries
- `shell_exec()` / `eval()` with unsanitised input
- Missing CSRF tokens
- `unserialize()` on user-controlled data
- `LIBXML_NOENT` enabling XXE
- Hardcoded secrets and credentials
- Missing authentication on sensitive endpoints
- Path traversal with incomplete sanitisation

---

## License

MIT — free to use for educational and research purposes.
