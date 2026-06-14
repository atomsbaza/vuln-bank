<?php
// ============================================================
//  VulnBank – Account Report Generator
//  CWE-89: Second-Order SQL Injection
//
//  Input is safely stored in the DB at registration time,
//  but retrieved and re-used in a NEW SQL query without
//  parameterisation — because "data from the DB is trusted".
//
//  Attack:
//    1. Register with username: admin'--
//    2. Visit this page → username fetched from DB, injected into report query
//    3. SQL becomes: SELECT * FROM ... WHERE owner = 'admin'--'
//       which bypasses the WHERE clause
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$uid = (int)$_SESSION['user_id'];

// Step 1: safely fetch current user's username from DB
$me = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();
$username = $me['username']; // looks safe — came from the DB, right?

$report = [];
$sql_shown = '';
$error = '';

if (isset($_GET['generate'])) {
    // Step 2: CWE-89 SECOND-ORDER SQL INJECTION
    // $username came from the DB so the developer trusts it.
    // But it was stored unsanitised at registration time.
    // If username = "admin'--", this query becomes:
    //   SELECT * FROM transactions ... WHERE u1.username = 'admin'--' OR ...
    // The -- comments out the rest, returning all transactions.
    $sql_shown = "SELECT t.*, u1.username AS sender, u2.username AS recipient
FROM transactions t
LEFT JOIN users u1 ON t.from_user = u1.id
LEFT JOIN users u2 ON t.to_user = u2.id
WHERE u1.username = '$username' OR u2.username = '$username'
ORDER BY t.created_at DESC";

    try {
        $report = db()->query($sql_shown)->fetchAll();
    } catch (Exception $e) {
        $error = 'DB error: ' . $e->getMessage(); // A05: raw error
    }
}
?>

<div class="row justify-content-center">
  <div class="col-md-9">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-89 Second-Order SQLi</span> — username stored safely but re-used unsanitised in report query
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Monthly Transaction Report</div>
      <div class="card-body">
        <p>Generating report for: <strong><?= htmlspecialchars($username) ?></strong></p>

        <?php if ($error): ?>
        <div class="alert alert-danger"><?= $error ?></div>
        <?php endif; ?>

        <?php if ($sql_shown): ?>
        <div class="p-2 bg-light border rounded mb-3" style="font-size:.78rem">
          <strong>SQL executed (second-order injection visible here):</strong><br>
          <code><?= htmlspecialchars($sql_shown) ?></code>
        </div>
        <?php endif; ?>

        <a href="report.php?generate=1" class="btn btn-primary">Generate My Report</a>
      </div>
    </div>

    <?php if ($report): ?>
    <div class="card shadow">
      <div class="card-header"><?= count($report) ?> transactions found</div>
      <div class="table-responsive">
        <table class="table table-sm mb-0">
          <thead><tr><th>ID</th><th>From</th><th>To</th><th>Amount</th><th>Description</th><th>Date</th></tr></thead>
          <tbody>
          <?php foreach ($report as $r): ?>
          <tr>
            <td><?= $r['id'] ?></td>
            <td><?= htmlspecialchars($r['sender'] ?? '?') ?></td>
            <td><?= htmlspecialchars($r['recipient'] ?? '?') ?></td>
            <td>$<?= number_format($r['amount'], 2) ?></td>
            <td><?= $r['description'] ?></td>
            <td style="font-size:.8rem"><?= $r['created_at'] ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php endif; ?>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body" style="font-size:.82rem">
        <strong>Second-order SQLi steps:</strong><br>
        1. Go to <a href="register.php">register.php</a> and create account with username: <code>' UNION SELECT 1,2,3,4,5,6,7--</code><br>
        2. Log in as that user<br>
        3. Visit this page and click "Generate My Report"<br>
        4. The injected username is fetched from DB and placed directly into the report SQL<br>
        5. The UNION payload leaks data from other tables<br><br>
        <strong>Why it's hard to detect:</strong> The dangerous value is in the DB, not in the current HTTP request.
        Taint analysis must cross the DB storage boundary.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
