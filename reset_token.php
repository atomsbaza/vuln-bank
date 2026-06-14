<?php
// ============================================================
//  VulnBank – Reset Token Redemption
//  CWE-330: Token stored and compared in plaintext, no expiry enforced
//  CWE-640: Weak Password Recovery Mechanism
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$token = $_GET['token'] ?? $_POST['token'] ?? '';
$msg = $error = '';
$user = null;

if ($token) {
    // A09: No rate limiting on token guessing
    // CWE-330: Token is just md5(time()+email) — brute-forceable
    $row = db()->query(
        "SELECT rt.*, u.* FROM reset_tokens rt
         JOIN users u ON rt.user_id = u.id
         WHERE rt.token = '$token' AND rt.used = 0"
        // CWE-640: expiry is stored but never checked in this query
    )->fetch();

    if ($row) {
        $user = $row;
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['new_password'])) {
            $new = $_POST['new_password'];
            db()->exec("UPDATE users SET password = '" . md5($new) . "' WHERE id = " . (int)$row['user_id']);
            // Don't mark token as used — can be replayed!
            // db()->exec("UPDATE reset_tokens SET used=1 WHERE token='$token'");
            $msg = "Password updated! <a href='index.php'>Login now</a>";
            $user = null;
        }
    } else {
        $error = 'Invalid or expired token.';
    }
}

require '_header.php';
?>
<div class="row justify-content-center">
  <div class="col-md-5">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-330 Predictable token</span>
      <span class="badge-vuln">CWE-640 Token not invalidated after use</span>
    </div>
    <div class="card shadow">
      <div class="card-header">Reset Password</div>
      <div class="card-body">
        <?php if ($error): ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($msg):   ?><div class="alert alert-success"><?= $msg ?></div><?php endif; ?>

        <?php if ($user): ?>
        <p>Resetting password for: <strong><?= htmlspecialchars($user['username']) ?></strong></p>
        <form method="POST">
          <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
          <div class="form-group mb-3">
            <label>New Password <span class="vuln-label">[token reusable — not invalidated after reset]</span></label>
            <input type="password" name="new_password" class="form-control" required>
          </div>
          <button class="btn btn-danger w-100">Reset Password</button>
        </form>
        <?php elseif (!$token): ?>
        <p class="text-muted">Access this page via the link in <a href="forgot.php">Forgot Password</a>.</p>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>
<?php require '_footer.php'; ?>
