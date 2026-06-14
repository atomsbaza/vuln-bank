<?php
// ============================================================
//  VulnBank – Transaction History
//  INTENTIONAL VULNERABILITIES:
//    A01 – IDOR: ?user_id= shows any user's full transaction history
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

// A01: IDOR – no ownership check on user_id parameter
// Try: transactions.php?user_id=1 → see admin's transactions
//      transactions.php?user_id=4 → see charlie's transactions
$uid = isset($_GET['user_id']) ? (int)$_GET['user_id'] : (int)$_SESSION['user_id'];

$account = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();
$txns    = db()->query("
    SELECT t.*, u1.username AS sender, u2.username AS recipient
    FROM   transactions t
    LEFT JOIN users u1 ON t.from_user = u1.id
    LEFT JOIN users u2 ON t.to_user   = u2.id
    WHERE  t.from_user = $uid OR t.to_user = $uid
    ORDER  BY t.created_at DESC
")->fetchAll();
?>

<div class="row justify-content-center">
  <div class="col-md-9">
    <?php if ($uid !== (int)$_SESSION['user_id']): ?>
    <div class="alert alert-warning">
      <strong>⚠️ A01 IDOR:</strong> Viewing transaction history for
      <strong><?= htmlspecialchars($account['username'] ?? "User #$uid") ?></strong>
      — no ownership check performed on <code>?user_id=</code>.
    </div>
    <?php endif; ?>

    <div class="card shadow">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>
          Transaction History –
          <?= htmlspecialchars($account['username'] ?? "User #$uid") ?>
          <span class="vuln-label">[A01 IDOR: change ?user_id=]</span>
        </span>
        <div>
          <?php foreach (db()->query("SELECT id,username FROM users") as $u): ?>
          <a href="transactions.php?user_id=<?= $u['id'] ?>" class="btn btn-xs btn-outline-secondary btn-sm"
             style="font-size:.75rem">
            <?= htmlspecialchars($u['username']) ?>
          </a>
          <?php endforeach; ?>
        </div>
      </div>
      <?php if (empty($txns)): ?>
      <div class="card-body text-muted">No transactions.</div>
      <?php else: ?>
      <div class="table-responsive">
        <table class="table table-hover mb-0">
          <thead><tr><th>#</th><th>Date</th><th>From</th><th>To</th><th>Amount</th><th>Description</th></tr></thead>
          <tbody>
          <?php foreach ($txns as $t): ?>
          <tr>
            <td><?= $t['id'] ?></td>
            <td style="font-size:.82rem"><?= $t['created_at'] ?></td>
            <td><?= htmlspecialchars($t['sender'] ?? 'System') ?></td>
            <td><?= htmlspecialchars($t['recipient'] ?? '-') ?></td>
            <td class="<?= $t['to_user'] == $uid ? 'text-success' : 'text-danger' ?> fw-bold">
              <?= $t['to_user'] == $uid ? '+' : '−' ?>$<?= number_format(abs($t['amount']),2) ?>
            </td>
            <!-- A03: description not HTML-escaped -->
            <td><?= $t['description'] ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
