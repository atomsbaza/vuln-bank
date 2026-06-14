<?php
// ============================================================
//  VulnBank – Registration
//  INTENTIONAL VULNERABILITIES:
//    A01 – Hidden 'role' field accepted from user input (mass assignment)
//    A04 – No password strength requirement, no email verification
//    A07 – Accepts any password (even 1 char)
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$error = $success = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $email    = trim($_POST['email'] ?? '');
    $security_q = $_POST['security_q'] ?? 'What is your pet name?';
    $security_a = $_POST['security_a'] ?? '';

    // A01: Mass assignment – role taken directly from hidden form field
    // Attacker sets <input name="role" value="admin"> in DevTools
    $role = $_POST['role'] ?? 'user';

    // A04: No password strength check
    // A07: Single character password is accepted
    if (!$username || !$password) {
        $error = 'Username and password are required.';
    } else {
        $acct = 'VB-' . str_pad(rand(1000, 9999), 7, '0', STR_PAD_LEFT);
        try {
            // A03: username not sanitised before insert (SQLi possible here too)
            db()->prepare(
                "INSERT INTO users (username,password,email,role,account_number,security_q,security_a)
                 VALUES (?,?,?,?,?,?,?)"
            )->execute([
                $username,
                md5($password),  // A02: MD5, no salt
                $email,
                $role,           // A01: attacker-controlled role
                $acct,
                $security_q,
                $security_a,
            ]);
            $success = "Account created! Account number: <strong>$acct</strong> &nbsp;<a href='index.php'>Login now</a>";
        } catch (Exception $e) {
            $error = 'Username already taken or error: ' . $e->getMessage(); // A05: raw error
        }
    }
}
?>
<?php require '_header.php'; ?>

<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="alert-vuln">
      ⚠️ <strong>A01 Challenge:</strong> Inspect the hidden <code>role</code> field and change it to <code>admin</code> before submitting.
    </div>

    <div class="card shadow">
      <div class="card-body p-4">
        <h3 class="text-center mb-4">Create Account</h3>

        <?php if ($error):   ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="alert alert-success"><?= $success ?></div><?php endif; ?>

        <form method="POST">
          <div class="form-group mb-3">
            <label>Username</label>
            <input type="text" name="username" class="form-control" required>
          </div>
          <div class="form-group mb-3">
            <label>
              Password
              <span class="vuln-label">[A07: no strength check]</span>
            </label>
            <!-- A04/A07: minlength=1, any password accepted -->
            <input type="password" name="password" class="form-control" minlength="1" required>
          </div>
          <div class="form-group mb-3">
            <label>Email (optional)</label>
            <input type="text" name="email" class="form-control">
          </div>
          <div class="form-group mb-3">
            <label>Security Question</label>
            <input type="text" name="security_q" class="form-control" value="What is your pet name?">
          </div>
          <div class="form-group mb-3">
            <label>Security Answer</label>
            <input type="text" name="security_a" class="form-control">
          </div>

          <!-- A01: MASS ASSIGNMENT – role is a hidden field the user can modify -->
          <!-- Change value="user" to value="admin" in DevTools to become admin -->
          <input type="hidden" name="role" value="user">

          <button class="btn btn-primary w-100">Register</button>
        </form>
        <p class="text-center mt-2"><a href="index.php">Already have an account?</a></p>
      </div>
    </div>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>Hint:</strong> Open DevTools → Elements, find <code>&lt;input type="hidden" name="role" value="user"&gt;</code>
        and change it to <code>value="admin"</code> before submitting.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
