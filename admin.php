<?php
// ============================================================
//  VulnBank – Admin Panel
//  INTENTIONAL VULNERABILITIES:
//    A01 – Broken access control: role check bypassed via cookie
//    A05 – Exposes all user records including password hashes
//    A07 – Multiple bypass vectors (cookie, URL param)
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

// ─────────────────────────────────────────────────────────────
//  A01: Broken Access Control – multiple bypass vectors:
//
//  1. Cookie override:  Set cookie admin_override=vulnbank_admin in DevTools
//  2. URL parameter:    admin.php?debug=1  (security by obscurity)
//  3. Register as admin via mass-assignment on register.php
//
//  The legitimate role check (session role === 'admin') is only ONE of three
//  paths – any of the others grants full access to a non-admin user.
// ─────────────────────────────────────────────────────────────
$is_admin = (
    $_SESSION['role'] === 'admin'                         // legitimate path
    || ($_COOKIE['admin_override'] ?? '') === 'vulnbank_admin' // A01: cookie bypass
    || ($_GET['debug'] ?? '')    === '1'                  // A01: URL param bypass
);

if (!$is_admin) {
    require '_header.php';
    echo '<div class="alert alert-danger">
            <h4>Access Denied</h4>
            <p>You need admin privileges. But there are ways around this...</p>
            <p><strong>Hint:</strong> Set a cookie <code>admin_override=vulnbank_admin</code> in DevTools,
               or append <code>?debug=1</code> to the URL, or register with <code>role=admin</code>.</p>
          </div>';
    require '_footer.php';
    exit;
}

// ── Admin actions ─────────────────────────────────────────────
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['delete_user'])) {
        $del_id = (int)$_POST['delete_user'];
        if ($del_id !== 1) { // protect admin account 1
            db()->exec("DELETE FROM users WHERE id = $del_id");
            $msg = "User #$del_id deleted.";
        }
    }
    if (isset($_POST['reset_balance'])) {
        $rid = (int)$_POST['reset_balance'];
        db()->exec("UPDATE users SET balance = 5000 WHERE id = $rid");
        $msg = "Balance reset for user #$rid.";
    }
}

$users = db()->query("SELECT * FROM users ORDER BY id")->fetchAll();
$txns  = db()->query("
    SELECT t.*, u1.username AS sender, u2.username AS recipient
    FROM transactions t
    LEFT JOIN users u1 ON t.from_user = u1.id
    LEFT JOIN users u2 ON t.to_user   = u2.id
    ORDER BY t.created_at DESC LIMIT 20
")->fetchAll();

require '_header.php';
?>

<div class="alert-vuln">
  ⚠️ <strong>A01 Bypass used:</strong>
  <?php
  if ($_SESSION['role'] === 'admin') echo 'Legitimate admin session.';
  elseif (($_COOKIE['admin_override'] ?? '') === 'vulnbank_admin') echo 'Cookie bypass: <code>admin_override=vulnbank_admin</code>';
  elseif (($_GET['debug'] ?? '') === '1') echo 'URL bypass: <code>?debug=1</code>';
  ?>
</div>

<h4 class="mb-3">🔧 Admin Panel
  <span class="badge-vuln">A01 Broken Access Control</span>
  <span class="badge-vuln">A05 Sensitive Data Exposed</span>
</h4>

<?php if ($msg): ?><div class="alert alert-info"><?= $msg ?></div><?php endif; ?>

<!-- A05: All user data including MD5 hashes exposed -->
<div class="card shadow mb-4">
  <div class="card-header bg-danger text-white">
    All Users
    <span style="font-size:.8rem">[A05: password hashes visible – crack at crackstation.net]</span>
  </div>
  <div class="table-responsive">
    <table class="table table-hover table-sm mb-0">
      <thead>
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Balance</th>
            <th>Account</th><th>Password (MD5)</th><th>Actions</th></tr>
      </thead>
      <tbody>
      <?php foreach ($users as $u): ?>
      <tr>
        <td><?= $u['id'] ?></td>
        <td><?= htmlspecialchars($u['username']) ?></td>
        <td><?= htmlspecialchars($u['email']) ?></td>
        <td><span class="badge <?= $u['role']==='admin'?'badge-warning':'badge-secondary' ?>"><?= $u['role'] ?></span></td>
        <td>$<?= number_format($u['balance'],2) ?></td>
        <td><?= $u['account_number'] ?></td>
        <!-- A05: MD5 hashes exposed – trivially crackable for common passwords -->
        <td><code style="font-size:.72rem"><?= $u['password'] ?></code></td>
        <td>
          <form method="POST" style="display:inline">
            <input type="hidden" name="reset_balance" value="<?= $u['id'] ?>">
            <button class="btn btn-xs btn-outline-info" style="font-size:.75rem">Reset $</button>
          </form>
          <?php if ($u['id'] !== 1): ?>
          <form method="POST" style="display:inline">
            <input type="hidden" name="delete_user" value="<?= $u['id'] ?>">
            <button class="btn btn-xs btn-outline-danger" style="font-size:.75rem"
                    onclick="return confirm('Delete?')">Del</button>
          </form>
          <?php endif; ?>
        </td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<div class="card shadow">
  <div class="card-header">Recent Transactions (All Users)</div>
  <div class="table-responsive">
    <table class="table table-sm mb-0">
      <thead><tr><th>ID</th><th>From</th><th>To</th><th>Amount</th><th>Description</th><th>Date</th></tr></thead>
      <tbody>
      <?php foreach ($txns as $t): ?>
      <tr>
        <td><?= $t['id'] ?></td>
        <td><?= htmlspecialchars($t['sender'] ?? '?') ?></td>
        <td><?= htmlspecialchars($t['recipient'] ?? '?') ?></td>
        <td>$<?= number_format($t['amount'],2) ?></td>
        <!-- A03: description not escaped here either -->
        <td><?= $t['description'] ?></td>
        <td style="font-size:.8rem"><?= $t['created_at'] ?></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<?php require '_footer.php'; ?>
