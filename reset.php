<?php
// ============================================================
//  VulnBank – Password Reset
//  INTENTIONAL VULNERABILITIES:
//    A07 – Reset without email verification; only a guessable security question
//    A07 – No rate limiting on guesses
//    A05 – Security question answer hinted in HTML comments
//    A02 – New password stored as MD5
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$step    = (int)($_POST['step'] ?? $_GET['step'] ?? 1);
$error   = $success = '';
$user    = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Step 1: Find account by username
    if ($step === 1) {
        $username = trim($_POST['username'] ?? '');
        // A03: SQLi here too (though minor – no data returned to attacker)
        $user = db()->query("SELECT * FROM users WHERE username = '$username'")->fetch();
        if (!$user) {
            $error = 'No account found with that username.';
            $step  = 1;
        } else {
            $step = 2;
        }
    }

    // Step 2: Answer security question
    elseif ($step === 2) {
        $uid    = (int)($_POST['uid'] ?? 0);
        $answer = strtolower(trim($_POST['security_a'] ?? ''));
        $user   = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();

        if (!$user) { $error = 'Session error.'; $step = 1; }
        else {
            // A07: Simple string compare, no lockout, case-insensitive only
            // A07: Security questions are guessable (pet names, birth cities)
            if ($answer === strtolower($user['security_a'])) {
                $step = 3;
            } else {
                // A09: Failed reset attempts not logged
                $error = 'Wrong answer. Try again.';
                $step  = 2;
            }
        }
    }

    // Step 3: Set new password
    elseif ($step === 3) {
        $uid      = (int)($_POST['uid'] ?? 0);
        $new_pass = $_POST['new_password'] ?? '';
        // A07: No minimum length enforced
        // A02: Stored as MD5
        db()->exec("UPDATE users SET password = '" . md5($new_pass) . "' WHERE id = $uid");
        // A09: Password change not logged or alerted via email
        $success = 'Password updated! <a href="index.php">Sign in</a>';
        $step    = 1;
    }
}

require '_header.php';
?>

<div class="row justify-content-center">
  <div class="col-md-5">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A07 No email verification</span>
      <span class="badge-vuln">A07 No lockout</span>
    </div>

    <div class="card shadow">
      <div class="card-header">Password Reset</div>
      <div class="card-body">
        <?php if ($error):   ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="alert alert-success"><?= $success ?></div><?php endif; ?>

        <?php if ($step === 1): ?>
        <form method="POST">
          <input type="hidden" name="step" value="1">
          <div class="form-group mb-3">
            <label>Username</label>
            <input type="text" name="username" class="form-control" required>
          </div>
          <button class="btn btn-primary w-100">Find Account</button>
        </form>

        <?php elseif ($step === 2 && $user): ?>
        <!-- A05: Security question answer leaked in HTML comment -->
        <!-- Hint: answer is "<?= $user['security_a'] ?>" -->
        <form method="POST">
          <input type="hidden" name="step" value="2">
          <input type="hidden" name="uid"  value="<?= $user['id'] ?>">
          <div class="form-group mb-2">
            <label>Security Question</label>
            <p class="form-control-plaintext text-muted"><?= htmlspecialchars($user['security_q']) ?></p>
          </div>
          <div class="form-group mb-3">
            <label>Your Answer
              <span class="vuln-label">[A07: no lockout – brute-force away]</span>
            </label>
            <input type="text" name="security_a" class="form-control" required>
            <small class="text-muted">Hint: check the HTML source of this page (View Source).</small>
          </div>
          <button class="btn btn-warning w-100">Verify Answer</button>
        </form>

        <?php elseif ($step === 3 && $user): ?>
        <form method="POST">
          <input type="hidden" name="step" value="3">
          <input type="hidden" name="uid"  value="<?= $user['id'] ?>">
          <div class="form-group mb-3">
            <label>New Password
              <span class="vuln-label">[A07: 1 char accepted; A02: stored as MD5]</span>
            </label>
            <input type="password" name="new_password" class="form-control" minlength="1" required>
          </div>
          <button class="btn btn-danger w-100">Reset Password</button>
        </form>
        <?php endif; ?>

        <p class="text-center mt-3"><a href="index.php">Back to Login</a></p>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
