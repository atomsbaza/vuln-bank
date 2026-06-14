<?php
// ============================================================
//  VulnBank – Dashboard
//  INTENTIONAL VULNERABILITIES:
//    A01 – IDOR: ?id= lets any authenticated user view any account
//    A02 – Balance, email, role exposed in HTML source comments
//    A03 – XSS in transaction description (not escaped in output)
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

// A01: IDOR – no check that $id belongs to current session user
// Try: dashboard.php?id=1  →  see admin's $999,999
//      dashboard.php?id=4  →  see charlie's $87,500
$id = isset($_GET['id']) ? (int)$_GET['id'] : $_SESSION['user_id'];

// A03: Direct interpolation in query (though id is cast to int here)
$account = db()->query("SELECT * FROM users WHERE id = $id")->fetch();

if (!$account) {
    echo '<div class="alert alert-danger">Account not found.</div>';
    require '_footer.php'; exit;
}

// Recent transactions for the viewed account
$txns = db()->query("
    SELECT t.*, u1.username AS sender, u2.username AS recipient
    FROM   transactions t
    LEFT JOIN users u1 ON t.from_user = u1.id
    LEFT JOIN users u2 ON t.to_user   = u2.id
    WHERE  t.from_user = {$id} OR t.to_user = {$id}
    ORDER  BY t.created_at DESC LIMIT 8
")->fetchAll();
?>

<?php if ($id !== (int)$_SESSION['user_id']): ?>
<div class="alert alert-warning">
  <strong>⚠️ A01 IDOR:</strong> You are viewing <strong><?= htmlspecialchars($account['username']) ?></strong>'s account (ID <?= $id ?>).
  You should not have access to this – but there is no ownership check on the <code>?id=</code> parameter.
</div>
<?php endif; ?>

<div class="row">
  <!-- ── Left: Account card ─────────────────────────────── -->
  <div class="col-md-4">
    <div class="card mb-4 shadow-sm">
      <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <strong>Account</strong>
        <?php if ($account['role'] === 'admin'): ?>
          <span class="badge" style="background:#c8a010">ADMIN</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <div class="balance-hero">$<?= number_format($account['balance'], 2) ?></div>
        <p class="text-muted mb-3">Available Balance</p>
        <table class="table table-sm table-borderless mb-0">
          <tr><th>Name</th>   <td><?= htmlspecialchars($account['username']) ?></td></tr>
          <tr><th>Account</th><td><?= $account['account_number'] ?></td></tr>
          <tr><th>Email</th>  <td><?= htmlspecialchars($account['email']) ?></td></tr>
          <!-- A02: Sensitive fields exposed in rendered HTML -->
          <tr><th>Role</th>   <td><?= $account['role'] ?></td></tr>
          <tr><th>User ID</th><td><?= $account['id'] ?></td></tr>
        </table>
        <hr>
        <a href="transfer.php" class="btn btn-success btn-sm">Transfer</a>
        <a href="transactions.php?user_id=<?= $id ?>" class="btn btn-outline-secondary btn-sm">All Transactions</a>
      </div>
    </div>

    <!-- A01: Enumerating all accounts helps attackers find IDs to target -->
    <div class="card shadow-sm">
      <div class="card-header">
        All Accounts
        <span class="vuln-label">[A01: exposes all user IDs]</span>
      </div>
      <ul class="list-group list-group-flush">
        <?php foreach (db()->query("SELECT id,username,account_number FROM users ORDER BY id") as $u): ?>
        <li class="list-group-item d-flex justify-content-between align-items-center py-2">
          <a href="dashboard.php?id=<?= $u['id'] ?>"><?= htmlspecialchars($u['username']) ?></a>
          <small class="text-muted"><?= $u['account_number'] ?></small>
        </li>
        <?php endforeach; ?>
      </ul>
    </div>
  </div>

  <!-- ── Right: Transactions ───────────────────────────── -->
  <div class="col-md-8">
    <div class="card shadow-sm">
      <div class="card-header">Recent Transactions</div>
      <?php if (empty($txns)): ?>
        <div class="card-body text-muted">No transactions yet.</div>
      <?php else: ?>
      <div class="table-responsive">
        <table class="table table-hover mb-0">
          <thead><tr><th>Date</th><th>From</th><th>To</th><th>Amount</th><th>Description</th></tr></thead>
          <tbody>
          <?php foreach ($txns as $t): ?>
          <tr>
            <td style="font-size:.82rem"><?= $t['created_at'] ?></td>
            <td><?= htmlspecialchars($t['sender'] ?? 'System') ?></td>
            <td><?= htmlspecialchars($t['recipient'] ?? '-') ?></td>
            <td class="<?= $t['to_user'] == $id ? 'text-success' : 'text-danger' ?> fw-bold">
              <?= $t['to_user'] == $id ? '+' : '−' ?>$<?= number_format(abs($t['amount']), 2) ?>
            </td>
            <!-- A03: description is NOT escaped → stored XSS possible via transfer form -->
            <td><?= $t['description'] ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>
    </div>

    <!-- Community messages (stored XSS) -->
    <div class="card shadow-sm mt-3">
      <div class="card-header">
        Community Board
        <span class="vuln-label">[A03: stored XSS in messages]</span>
      </div>
      <ul class="list-group list-group-flush">
        <?php foreach (db()->query("SELECT * FROM messages ORDER BY created_at DESC") as $m): ?>
        <li class="list-group-item py-2">
          <strong><?= htmlspecialchars($m['username']) ?></strong>
          <small class="text-muted ms-2"><?= $m['created_at'] ?></small><br>
          <!-- A03: content NOT escaped → post <script>alert(1)</script> via profile.php -->
          <?= $m['content'] ?>
        </li>
        <?php endforeach; ?>
      </ul>
    </div>
  </div>
</div>

<!--
  A02: Sensitive data in HTML comments (visible in View Source)
  Session user  : <?= $_SESSION['username'] ?> (id=<?= $_SESSION['user_id'] ?>, role=<?= $_SESSION['role'] ?>)
  Viewing account id: <?= $id ?>
  Balance raw   : <?= $account['balance'] ?>
  Password hash : <?= $account['password'] ?>
-->

<?php require '_footer.php'; ?>
