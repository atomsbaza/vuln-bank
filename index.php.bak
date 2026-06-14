<?php
// ============================================================
//  VulnBank – Login
//  INTENTIONAL VULNERABILITIES:
//    A03 – SQL injection via unsanitised $username
//    A07 – No session regeneration, no lockout, no brute-force delay
//    A02 – "Remember me" stores plaintext password in base64 cookie
//    A09 – No login events logged
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();

if (isset($_SESSION['user_id'])) { header('Location: dashboard.php'); exit; }

// A02/A07: Auto-login from remember-me cookie containing plaintext credentials
if (isset($_COOKIE['remember_user']) && !isset($_SESSION['user_id'])) {
    $parts = explode(':', base64_decode($_COOKIE['remember_user']), 2);
    if (count($parts) === 2) {
        [$u, $p] = $parts;
        // Still injectable – $u comes from a user-controlled cookie
        $user = db()->query("SELECT * FROM users WHERE username='$u' AND password='".md5($p)."'")->fetch();
        if ($user) {
            $_SESSION['user_id']  = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role']     = $user['role'];
            header('Location: dashboard.php'); exit;
        }
    }
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // ─────────────────────────────────────────────────────────
    //  A03: SQL INJECTION
    //  The username is interpolated directly into the query.
    //
    //  Classic bypass  →  username: admin' --
    //  Resulting SQL   →  SELECT * FROM users WHERE username = 'admin' --' AND password='...'
    //
    //  UNION exfil     →  ' UNION SELECT 1,'x',md5('x'),'e@e.com','admin',0,'VB-X','q','a'--
    // ─────────────────────────────────────────────────────────
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '" . md5($password) . "'";

    try {
        $user = db()->query($sql)->fetch();
    } catch (Exception $e) {
        // A05: Raw DB error shown to user – reveals schema
        $error = 'Database error: ' . $e->getMessage();
        $user  = false;
    }

    if ($user) {
        // A07: No session_regenerate_id() → session fixation attack possible
        $_SESSION['user_id']  = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role']     = $user['role'];

        // A02/A07: Store plaintext credentials in a cookie encoded only with base64
        if (!empty($_POST['remember'])) {
            setcookie(
                'remember_user',
                base64_encode($username . ':' . $password),
                time() + 86400 * 30,
                '/',
                '',    // no domain restriction
                false, // A02: no Secure flag – sent over plain HTTP
                false  // A02: no HttpOnly – readable by JS
            );
        }
        // A09: Successful login not logged anywhere
        header('Location: dashboard.php'); exit;
    } elseif (!$error) {
        // A09: Failed login not counted → unlimited brute-force
        $error = 'Invalid username or password.';
    }
}
?>
<?php require '_header.php'; ?>

<div class="row justify-content-center">
  <div class="col-md-5">
    <div class="alert-vuln">
      ⚠️ <strong>Training App</strong> – Intentionally vulnerable. For ethical hacking practice only.
    </div>

    <div class="card shadow">
      <div class="card-body p-4">
        <h3 class="text-center mb-4">🔒 Sign in to VulnBank</h3>

        <?php if ($error): ?>
          <!-- A05: Error message may leak DB schema details -->
          <div class="alert alert-danger"><?= $error ?></div>
        <?php endif; ?>

        <form method="POST">
          <div class="form-group mb-3">
            <label>Username</label>
            <input type="text" name="username" class="form-control" autofocus
                   placeholder="Try: admin' --">
          </div>
          <div class="form-group mb-3">
            <label>Password</label>
            <input type="password" name="password" class="form-control"
                   placeholder="Try: anything (with SQLi above)">
          </div>
          <div class="form-check mb-3">
            <input type="checkbox" name="remember" id="rem" class="form-check-input">
            <label for="rem" class="form-check-label">
              Remember me
              <span class="vuln-label">[A02: stores plaintext pass in cookie]</span>
            </label>
          </div>
          <button class="btn btn-primary btn-block w-100">Sign In</button>
        </form>

        <hr>
        <p class="text-center mb-1">
          <a href="register.php">Create account</a> · <a href="reset.php">Forgot password?</a>
        </p>
        <!-- A05: Default credentials exposed in UI -->
        <div class="text-center mt-2" style="font-size:.8rem;color:#888">
          <strong>Demo logins:</strong><br>
          admin / admin123 &nbsp;·&nbsp; alice / password123<br>
          bob / letmein &nbsp;·&nbsp; charlie / charlie1
        </div>
      </div>
    </div>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>A03 SQLi hint:</strong> Username field is concatenated directly into SQL.<br>
        Try <code>admin' --</code> to comment out the password check.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
