<?php
// ============================================================
//  VulnBank – Money Transfer
//  INTENTIONAL VULNERABILITIES:
//    A08 – No CSRF token on the transfer form
//    A04 – Negative amounts allowed → steal money from own account
//    A03 – SQL injection in the description field
//    A09 – Transfers not logged to audit trail
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$me    = db()->query("SELECT * FROM users WHERE id = " . (int)$_SESSION['user_id'])->fetch();
$users = db()->query("SELECT id,username,account_number FROM users WHERE id != " . (int)$_SESSION['user_id'])->fetchAll();

$error = $success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $to_acct = trim($_POST['to_account'] ?? '');
    $amount  = $_POST['amount'] ?? 0;          // A04: not validated as positive
    $desc    = $_POST['description'] ?? '';    // A03: goes into SQL unescaped

    // A08: No CSRF token checked at all

    // Find recipient by account number
    // A03: $to_acct not sanitised → SQLi in account number lookup
    // Payload in to_account: VB-0001001' OR '1'='1
    $to_acct_clean = str_replace("'", "''", $to_acct); // "escaping" – bypassable with other techniques
    $recipient = db()->query("SELECT * FROM users WHERE account_number = '$to_acct'")->fetch();

    if (!$recipient) {
        $error = 'Recipient account not found.';
    } else {
        // A04: Negative amounts accepted → receiver gets debited, sender gets credited
        // Try: amount = -5000 to steal $5000 from recipient
        $amount = (float)$amount;

        // Deduct from sender, add to recipient
        db()->exec("UPDATE users SET balance = balance - $amount WHERE id = " . (int)$_SESSION['user_id']);
        db()->exec("UPDATE users SET balance = balance + $amount WHERE id = " . (int)$recipient['id']);

        // A03: SQL injection in description
        // Payload: ','),(1,1,99999,'hacked')--
        // (works when inserted into a VALUES list without parameterised query)
        $sql = "INSERT INTO transactions (from_user,to_user,amount,description)
                VALUES (" . (int)$_SESSION['user_id'] . "," . (int)$recipient['id'] . ",$amount,'$desc')";
        db()->exec($sql);

        // A09: No audit log entry, no email alert, no rate limiting
        $success = "Transferred $" . number_format(abs($amount), 2) . " to " . htmlspecialchars($recipient['username']) . ".";
        $me = db()->query("SELECT * FROM users WHERE id = " . (int)$_SESSION['user_id'])->fetch(); // refresh balance
    }
}
?>

<div class="row justify-content-center">
  <div class="col-md-7">
    <div class="alert-vuln">
      ⚠️ <strong>Vulnerabilities here:</strong>
      <span class="badge-vuln">A08 No CSRF</span>
      <span class="badge-vuln">A04 Negative amounts</span>
      <span class="badge-vuln">A03 SQLi in description</span>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header bg-primary text-white">Your Balance</div>
      <div class="card-body py-2">
        <span class="balance-hero">$<?= number_format($me['balance'], 2) ?></span>
        <span class="text-muted ms-2"><?= $me['account_number'] ?></span>
      </div>
    </div>

    <div class="card shadow">
      <div class="card-header">Transfer Funds</div>
      <div class="card-body">
        <?php if ($error):   ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="alert alert-success"><?= $success ?></div><?php endif; ?>

        <!-- A08: No CSRF token in this form -->
        <!-- Attacker can host: <form action="http://localhost:8080/transfer.php" ...><script>submit()</script> -->
        <form method="POST">
          <div class="form-group mb-3">
            <label>Recipient Account Number
              <span class="vuln-label">[A03: SQLi – try VB-0001001' OR '1'='1]</span>
            </label>
            <select name="to_account" class="form-control">
              <?php foreach ($users as $u): ?>
              <option value="<?= $u['account_number'] ?>">
                <?= htmlspecialchars($u['username']) ?> (<?= $u['account_number'] ?>)
              </option>
              <?php endforeach; ?>
            </select>
            <small class="text-muted">Or type a custom account number in the field below for injection testing</small>
          </div>
          <div class="form-group mb-2">
            <label>Custom Account (for testing)</label>
            <input type="text" name="to_account" class="form-control" placeholder="VB-0001002">
          </div>
          <div class="form-group mb-3">
            <label>Amount
              <span class="vuln-label">[A04: negative allowed → drains recipient]</span>
            </label>
            <div class="input-group">
              <div class="input-group-prepend"><span class="input-group-text">$</span></div>
              <input type="number" name="amount" class="form-control" step="0.01"
                     placeholder="e.g. 100 or -5000 to steal">
            </div>
          </div>
          <div class="form-group mb-3">
            <label>Description
              <span class="vuln-label">[A03: SQLi – try ','),(1,1,99999,'injected')--]</span>
            </label>
            <input type="text" name="description" class="form-control"
                   value="<?= htmlspecialchars($_POST['description'] ?? '') ?>"
                   placeholder="Payment for...">
          </div>
          <button class="btn btn-success w-100">Send Transfer</button>
        </form>
      </div>
    </div>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>A08 CSRF PoC:</strong> Save the snippet below as <code>csrf.html</code> and open it while logged in.<br>
        <code>&lt;form action="http://localhost:8080/transfer.php" method="POST"&gt;
&lt;input name="to_account" value="VB-0000001"&gt;
&lt;input name="amount" value="10000"&gt;
&lt;input name="description" value="hacked"&gt;
&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
