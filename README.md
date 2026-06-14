# VulnBank 🏦

> **A deliberately vulnerable PHP banking application for security training and LLM-powered scanner testing.**

VulnBank simulates a realistic online banking portal packed with **50+ intentional security vulnerabilities** across 30+ distinct vulnerability classes — covering all OWASP Top 10 categories plus PHP-specific flaws, cryptographic weaknesses, race conditions, injection variants, authentication edge cases, and more.

Use it to:
- Practice ethical hacking in a safe local environment
- Test and benchmark LLM-based SAST security code scanners
- Learn how each vulnerability looks in real PHP code

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
git clone https://github.com/atomsbaza/vuln-bank.git
cd vuln-bank
php -S localhost:8080
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

**Demo accounts:**

| Username | Password    | Role  | Balance   |
|----------|-------------|-------|-----------|
| admin    | admin123    | admin | $999,999  |
| alice    | password123 | user  | $15,000   |
| bob      | letmein     | user  | $3,200    |
| charlie  | charlie1    | user  | $87,500   |

---

## Vulnerabilities

### OWASP Top 10

| ID | Name | File(s) | Example Attack |
|----|------|---------|----------------|
| A01 | Broken Access Control | `dashboard.php`, `admin.php`, `register.php`, `transactions.php` | `?id=1` views admin account; cookie `admin_override=vulnbank_admin`; hidden `role=admin` field |
| A02 | Cryptographic Failures | `db.php`, `index.php`, `.env`, `_footer.php`, `crypto.php` | Unsalted MD5 passwords; base64 remember-me cookie contains plaintext password; AES-ECB mode |
| A03 | Injection (SQLi + XSS) | `index.php`, `search.php`, `transfer.php`, `profile.php`, `report.php` | Login: `admin' --`; UNION exfil in search; stored XSS in bio; second-order SQLi in report |
| A04 | Insecure Design | `transfer.php`, `register.php`, `loan.php` | Negative transfer steals money; integer overflow on loan amount; no email verification |
| A05 | Security Misconfiguration | `phpinfo.php`, `.env`, `config.php`, `backup.sql`, `debug.php` | `debug.php` dumps full env + DB, no auth; `backup.sql` web-accessible with creds in comments |
| A06 | Vulnerable Components | `_header.php`, `csti.php` | jQuery 1.12.4 (CVE-2020-11022), Bootstrap 4.0.0-alpha.6, AngularJS 1.6.9 (CSTI) |
| A07 | Auth Failures | `index.php`, `reset.php`, `forgot.php`, `2fa.php`, `logout.php` | No lockout; session fixation; predictable reset token `md5(time()+email)`; `mt_rand` OTP |
| A08 | Integrity Failures | `transfer.php`, `profile.php`, `extract.php` | No CSRF token; `unserialize()` on cookie; `extract($_POST)` overwrites auth flags |
| A09 | Logging Failures | Everywhere | Zero audit logging — logins, transfers, admin access, password resets all untracked |
| A10 | SSRF | `profile.php` | Avatar URL: `file:///etc/passwd` or `http://169.254.169.254/latest/meta-data/` |

### Injection Variants

| Vulnerability | CWE | File | Example |
|--------------|-----|------|---------|
| Command Injection | CWE-78 | `ping.php` | `127.0.0.1; cat .env` |
| Code Injection (eval) | CWE-94 | `eval.php` | `{{system('id')}}` in template |
| XXE — In-Band | CWE-611 | `export.php` | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| XXE — Billion Laughs | CWE-776 | `export.php` | Nested entity expansion DoS |
| Email Header Injection | CWE-93 | `contact.php` | Subject: `Help%0D%0ABcc: attacker@evil.com` |
| LFI / php://filter | CWE-98 | `lfi.php` | `?page=php://filter/convert.base64-encode/resource=db` |
| Client-Side Template Injection | CWE-94 | `csti.php` | `?name={{constructor.constructor('alert(1)')()}}` |
| Second-Order SQL Injection | CWE-89 | `report.php` | Register with `' UNION SELECT...--`, then generate report |
| NoSQL / LDAP patterns | CWE-943 | `api.php` | Documented in hints |

### Authentication & Session

| Vulnerability | CWE | File | Example |
|--------------|-----|------|---------|
| PHP Type Juggling (`==` bypass) | CWE-697 | `typejuggling.php` | Password `QNKCDZO` matches any `0e...` hash |
| Host Header Injection (reset poisoning) | CWE-644 | `forgot.php` | `Host: attacker.com` → reset link points to attacker |
| Predictable Reset Token | CWE-330 | `forgot.php`, `reset_token.php` | `md5(time() + email)` — only 120 candidates in ±60s |
| Token Not Invalidated After Use | CWE-640 | `reset_token.php` | Same token redeemable multiple times |
| Username Enumeration | CWE-204 | `forgot.php` | Different messages for valid vs. invalid emails |
| JWT `alg:none` / Weak Secret | CWE-347 | `jwt_api.php` | Set `alg:none`, remove signature; or crack secret `"secret"` |
| OAuth Missing State (CSRF) | CWE-352 | `oauth.php` | No `state` param → account-linking CSRF |
| OAuth `redirect_uri` Prefix Bypass | CWE-601 | `oauth.php` | `redirect_uri=http://localhost:8080/oauth.php.attacker.com` |
| Predictable 2FA OTP (`mt_rand`) | CWE-330 | `2fa.php` | Brute-force 1M combinations; no lockout |
| OTP Exposed in Response | CWE-640 | `2fa.php` | OTP shown in UI — readable by XSS |
| Session Fixation | CWE-384 | `index.php` | No `session_regenerate_id()` after login |
| Open Redirect | CWE-601 | `redirect.php` | `?url=//attacker.com` |

### Cryptographic Weaknesses

| Vulnerability | CWE | File | Example |
|--------------|-----|------|---------|
| AES-ECB Mode | CWE-327 | `crypto.php` | Identical blocks → identical ciphertext; blocks rearrangeable |
| CBC Padding Oracle | CWE-649 | `crypto.php` | Different error for padding vs. auth failure → plaintext recovery |
| Weak PRNG for CSRF Token | CWE-330 | `crypto.php` | `md5(mt_rand())` — seed recoverable with `php_mt_seed` |
| bcrypt Cost Too Low | CWE-916 | `crypto.php` | `cost=4` — crackable in seconds with hashcat |
| Static CBC IV | CWE-329 | `crypto.php` | Same plaintext prefix always produces same ciphertext block |
| Timing Attack on Signature | CWE-208 | `jwt_api.php` | `!==` short-circuits; use `hash_equals()` instead |

### Business Logic & Race Conditions

| Vulnerability | CWE | File | Example |
|--------------|-----|------|---------|
| Negative Transfer Amount | CWE-20 | `transfer.php` | `amount=-5000` credits attacker, debits victim |
| Integer Overflow on Loan | CWE-190 | `loan.php` | `total=99999999999999999999` → `(int)` wraps to negative monthly payment |
| Float Salami Attack | CWE-681 | `loan.php` | Sub-cent rounding loss per transaction; harvest at scale |
| Race Condition on Voucher | CWE-362 | `voucher.php` | 20 concurrent requests all pass `used=0` check before any UPDATE commits |
| `extract()` Variable Overwrite | CWE-915 | `extract.php` | POST `authorized=1` overwrites `$authorized = false` |
| API Mass Assignment / BOPLA | CWE-915 | `api.php` | `internal_credit_score`, `admin_notes` returned to all callers |

### Path Traversal & File Handling

| Vulnerability | CWE | File | Example |
|--------------|-----|------|---------|
| Path Traversal (bypass `str_replace`) | CWE-22 | `download.php` | `?file=....//....//etc/passwd` |
| Unrestricted File Upload | CWE-434 | `upload.php` | Upload `shell.php` → RCE at `/uploads/shell.php?cmd=id` |
| PHAR Deserialization | CWE-502 | `phar.php` | `getimagesize("phar://uploads/evil.gif")` triggers `__destruct()` — no `unserialize()` in source |
| php://filter LFI | CWE-98 | `lfi.php` | `?page=php://filter/convert.base64-encode/resource=db` → db.php source |

### Exposed Sensitive Files & Misconfiguration

| File | What It Exposes |
|------|----------------|
| `.env` | AWS keys, SMTP password, API tokens |
| `backup.sql` | Full DB dump with hashes + SSH/deploy creds in comments |
| `config.php` | Payment gateway keys, legacy DB creds, cipher key = `0000...` |
| `phpinfo.php` | Full PHP config, file paths, loaded extensions |
| `debug.php` | `$_SESSION`, `$_SERVER`, `$_ENV`, all DB users — no auth required |
| `index.php.bak`, `db.php.bak` | Source backup files discoverable via fuzzing |
| `composer.json` | Dependency confusion — private package without registry pin (CWE-427) |

### HTTP-Level & Client-Side

| Vulnerability | CWE | File | Example |
|--------------|-----|------|---------|
| No `X-Frame-Options` (Clickjacking) | CWE-1021 | All pages | Embed in transparent iframe, overlay fake UI |
| Insecure Cookie Flags | CWE-1004 | `index.php` | No `HttpOnly`, `Secure`, or `SameSite` on session cookie |
| HTTP Parameter Pollution | CWE-235 | `contact.php` | `amount=100&amount=9999` → PHP uses last value |
| CORS Wildcard | CWE-942 | `api.php` | `Access-Control-Allow-Origin: *` on authenticated data |
| TLS Verification Disabled | CWE-295 | `profile.php` | `CURLOPT_SSL_VERIFYPEER = false` on payment gateway calls |
| Verbose Error Disclosure | CWE-209 | All pages | Raw PDO exceptions with DB schema exposed to browser |

---

## File Structure

```
vuln-bank/
├── index.php          # Login (SQLi, session fixation, no lockout)
├── register.php       # Registration (mass assignment, weak passwords)
├── dashboard.php      # Dashboard (IDOR on ?id=, stored XSS in transactions)
├── transfer.php       # Transfer (no CSRF, negative amounts, SQLi in description)
├── transactions.php   # History (IDOR on ?user_id=)
├── profile.php        # Profile (stored XSS, SSRF, PHP unserialize cookie)
├── admin.php          # Admin panel (cookie/URL access control bypass)
├── search.php         # Search (UNION-based SQLi)
├── reset.php          # Password reset (security question, answer in source)
├── forgot.php         # Forgot password (host header injection, predictable token, enumeration)
├── reset_token.php    # Token redemption (token not invalidated after use)
├── report.php         # Transaction report (second-order SQL injection)
├── typejuggling.php   # Login v2 (PHP == magic hash bypass)
├── extract.php        # Wire transfer (extract() variable overwrite)
├── voucher.php        # Promo codes (race condition, non-atomic check-then-use)
├── loan.php           # Loan calculator (integer overflow, float salami)
├── ping.php           # Network diagnostic (command injection)
├── download.php       # File download (path traversal, str_replace bypass)
├── upload.php         # Photo upload (unrestricted .php upload → RCE)
├── phar.php           # Avatar validator (PHAR deserialization via getimagesize)
├── lfi.php            # Page loader (LFI, php://filter source disclosure)
├── export.php         # XML import/export (XXE, billion laughs)
├── eval.php           # Statement template (code injection via eval)
├── csti.php           # Investment calculator (AngularJS CSTI)
├── crypto.php         # Crypto demos (AES-ECB, padding oracle, weak PRNG, bcrypt cost=4)
├── jwt_api.php        # JWT API (alg:none, weak secret, BOPLA)
├── 2fa.php            # Two-factor auth (mt_rand OTP, no lockout, 24h lifetime)
├── oauth.php          # OAuth login (missing state, redirect_uri bypass)
├── contact.php        # Support form (email header injection, HTTP parameter pollution)
├── redirect.php       # Link handler (open redirect)
├── api.php            # JSON API (no auth, CORS *, SQLi, BOPLA)
├── debug.php          # Debug endpoint (full env dump, no auth)
├── admin.php          # Admin panel (multiple access control bypasses)
├── config.php         # Legacy config (payment keys, DB creds exposed)
├── phpinfo.php        # PHP info page (security misconfig)
├── hints.php          # 💡 Full guide: every vuln, payload, and impact
├── .env               # Exposed secrets (web-accessible)
├── backup.sql         # DB dump in webroot (hashes + SSH creds)
├── composer.json      # Dependency confusion (private package, no registry pin)
├── index.php.bak      # Source backup (discoverable via fuzzing)
└── db.php             # DB init (MD5 passwords, hardcoded secrets)
```

---

## Hints Page

Visit [http://localhost:8080/hints.php](http://localhost:8080/hints.php) for a full guide listing every vulnerability, where to find it, how to exploit it, and the impact.

---

## Use with an LLM Security Scanner

VulnBank is designed as a benchmark target for LLM-based SAST tools. The vulnerabilities are tiered by detection difficulty:

**Easy (pattern matching):**
- `shell_exec()` / `eval()` / `system()` with unsanitised input
- String-concatenated SQL queries
- `md5()` for password hashing
- `CURLOPT_SSL_VERIFYPEER = false`
- `LIBXML_NOENT` enabling XXE
- Hardcoded secrets and credentials
- Missing `HttpOnly`/`Secure` cookie flags

**Medium (taint flow required):**
- Path traversal through incomplete `str_replace('../')` defence
- `unserialize()` on user-controlled cookie
- `extract($_POST)` overwriting auth variables
- Host header (`$_SERVER['HTTP_HOST']`) in email links
- `mt_rand()` / `rand()` for security-critical tokens
- AES-ECB mode (`'AES-128-ECB'` in `openssl_encrypt`)

**Hard (semantic / cross-file reasoning):**
- Second-order SQLi — safe insert, dangerous re-use from DB in different file
- PHAR deserialization — `getimagesize()` on user path, no `unserialize()` visible
- PHP `==` magic hash bypass — semantic difference between `==` and `===`
- Race condition — absence of `BEGIN TRANSACTION` is the bug
- Business logic — missing `$amount > 0` check (no dangerous function, just missing guard)
- JWT `alg:none` — library-level trust of `alg` header field
- OAuth missing `state` — absence of a parameter is the vulnerability

---

## License

MIT — free to use for educational and research purposes.
