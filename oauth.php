<?php
// ============================================================
//  VulnBank – OAuth 2.0 Login (Misconfigured)
//  CWE-352: Missing CSRF protection on OAuth callback (no state)
//  CWE-601: Open redirect in redirect_uri validation (prefix match)
//  CWE-287: Implicit flow leaks tokens in URL fragment
//
//  Simulated OAuth flow — no real provider, demonstrates the
//  misconfiguration patterns in the PHP code itself.
// ============================================================
require_once 'db.php';
require '_header.php';

$step   = $_GET['step'] ?? 'start';
$error  = $msg = '';

// ── Step 1: Build authorization URL ──────────────────────────
if ($step === 'start') {
    // CWE-352: NO state parameter generated or stored
    // A real implementation: $state = bin2hex(random_bytes(16)); $_SESSION['oauth_state'] = $state;
    $auth_url = "https://accounts.google.example.com/oauth2/auth?" . http_build_query([
        'client_id'     => 'vulnbank-client-id',
        'redirect_uri'  => 'http://localhost:8080/oauth.php?step=callback',
        'response_type' => 'code',
        'scope'         => 'openid email profile',
        // 'state'      => $state,  ← MISSING: enables CSRF attack
    ]);
}

// ── Step 2: Handle callback ───────────────────────────────────
if ($step === 'callback') {
    $code  = $_GET['code']  ?? '';
    $state = $_GET['state'] ?? '';

    // CWE-352: No state validation at all
    // An attacker can initiate the OAuth flow, capture the auth URL,
    // and trick a victim into visiting it — the callback logs in the ATTACKER
    // as the victim (account linking CSRF)

    // Simulate token exchange (no real provider)
    if ($code || true) { // accepts any code including empty
        $fake_user = ['id' => 2, 'username' => 'alice', 'email' => 'alice@example.com', 'role' => 'user'];
        $_SESSION['user_id']  = $fake_user['id'];
        $_SESSION['username'] = $fake_user['username'];
        $_SESSION['role']     = $fake_user['role'];
        $msg = "✅ OAuth login successful as <strong>{$fake_user['username']}</strong> (state was never validated)";
    }
}

// ── Implicit flow demo ────────────────────────────────────────
// CWE-287: implicit flow returns access_token in URL fragment
// Logged in browser history, server logs, referrer headers
$implicit_url = "https://accounts.google.example.com/oauth2/auth?" . http_build_query([
    'client_id'     => 'vulnbank-client-id',
    'redirect_uri'  => 'http://localhost:8080/oauth.php?step=implicit',
    'response_type' => 'token',  // implicit: token in URL fragment
    'scope'         => 'openid',
]);

// ── redirect_uri validation (prefix match — bypassable) ──────
$allowed_prefix = 'http://localhost:8080/oauth.php';
$redir = $_GET['redirect_uri'] ?? '';
$redir_valid = str_starts_with($redir, $allowed_prefix);
// Bypass: http://localhost:8080/oauth.php.attacker.com/steal
// OR:     http://localhost:8080/oauth.php/../../../steal
?>

<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-352 No OAuth State</span>
      <span class="badge-vuln">CWE-601 redirect_uri prefix bypass</span>
      <span class="badge-vuln">CWE-287 Implicit flow token in URL</span>
    </div>

    <?php if ($msg):   ?><div class="alert alert-success"><?= $msg ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>

    <div class="card shadow mb-3">
      <div class="card-header">OAuth 2.0 – Login with Google</div>
      <div class="card-body">
        <p class="text-muted">Simulated OAuth — demonstrates the misconfiguration patterns, not a real Google login.</p>

        <a href="oauth.php?step=callback&code=fake_auth_code"
           class="btn btn-primary mb-2">
          Simulate OAuth Callback (no state validation)
        </a>

        <div class="p-3 bg-light rounded mt-2" style="font-size:.82rem">
          <strong>Authorization URL that would be generated:</strong><br>
          <code style="word-break:break-all"><?= isset($auth_url) ? htmlspecialchars($auth_url) : '' ?></code><br>
          <span class="text-danger">⚠ Notice: no <code>state</code> parameter</span>
        </div>
      </div>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">redirect_uri Validation (prefix match)</div>
      <div class="card-body" style="font-size:.82rem">
        <p>Allowed prefix: <code><?= htmlspecialchars($allowed_prefix) ?></code></p>
        <div class="input-group mb-2">
          <input type="text" id="ruri" class="form-control"
                 placeholder="http://localhost:8080/oauth.php.attacker.com/steal"
                 value="<?= htmlspecialchars($redir) ?>">
          <button class="btn btn-outline-secondary"
                  onclick="location.href='oauth.php?redirect_uri='+encodeURIComponent(document.getElementById('ruri').value)">
            Test Validation
          </button>
        </div>
        <?php if ($redir): ?>
        <div class="alert <?= $redir_valid ? 'alert-warning' : 'alert-success' ?> py-1">
          <code><?= htmlspecialchars($redir) ?></code><br>
          Validation result: <strong><?= $redir_valid ? '✅ ALLOWED (but is it really safe?)' : '❌ Blocked' ?></strong><br>
          <?php if ($redir_valid && $redir !== $allowed_prefix): ?>
          <span class="text-danger">⚠ Prefix match allows subpath bypass!</span>
          <?php endif; ?>
        </div>
        <?php endif; ?>
        <p>Bypass attempts:<br>
          <code>http://localhost:8080/oauth.php.attacker.com</code> — domain suffix<br>
          <code>http://localhost:8080/oauth.php/../evil</code> — path traversal<br>
          <code>http://localhost:8080/oauth.php?x=1&redirect_to=http://evil.com</code>
        </p>
      </div>
    </div>

    <div class="card hint-card shadow-sm">
      <div class="card-body" style="font-size:.8rem">
        <strong>OAuth CSRF (missing state) PoC:</strong><br>
        1. Attacker starts OAuth flow → gets auth URL with <code>?code=ATTACKER_CODE</code><br>
        2. Victim (logged into Google) is tricked into visiting callback URL<br>
        3. Callback links attacker's Google account to victim's VulnBank session<br>
        4. Attacker logs in with Google → now controls victim's bank account<br><br>
        <strong>Fix:</strong> Generate <code>$state = bin2hex(random_bytes(16))</code>, store in session,
        verify on callback: <code>$_GET['state'] === $_SESSION['oauth_state']</code>.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
