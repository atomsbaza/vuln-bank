<?php
// ============================================================
//  VulnBank – Voucher / Promo Code Redemption
//  CWE-362: Race Condition — non-atomic check-then-use
//  CWE-840: Voucher reusable due to missing atomic invalidation
//
//  The check (used=0?) and update (used=1) are two separate
//  SQL statements with NO transaction or row lock between them.
//  Concurrent requests both pass the check before either update commits.
//
//  PoC: send 20 parallel requests with the same code:
//    for i in {1..20}; do
//      curl -s -X POST http://localhost:8080/voucher.php \
//        -d "code=SAVE100&action=redeem" &
//    done; wait
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$uid    = (int)$_SESSION['user_id'];
$me     = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();
$result = $error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = strtoupper(trim($_POST['code'] ?? ''));

    // ── Step 1: CHECK (not locked) ────────────────────────────
    // CWE-362: No SELECT ... FOR UPDATE; no BEGIN TRANSACTION
    // Two concurrent requests can both read used=0 here
    $voucher = db()->query("SELECT * FROM vouchers WHERE code = '$code' AND used = 0")->fetch();

    if (!$voucher) {
        $error = "Voucher <strong>$code</strong> is invalid or already used.";
    } else {
        // Simulate processing delay (makes race condition easier to trigger)
        // usleep(100000); // 100ms — uncomment to make race more reproducible

        // ── Step 2: MARK USED (separate statement — race window) ─
        // Both concurrent requests reach here with voucher still unused
        db()->exec("UPDATE vouchers SET used=1, used_by=$uid WHERE code='$code'");

        // ── Step 3: CREDIT BALANCE ────────────────────────────
        $discount = $voucher['discount'];
        db()->exec("UPDATE users SET balance = balance + $discount WHERE id = $uid");
        $me = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();

        $result = "✅ Voucher <strong>$code</strong> redeemed! +$" . number_format($discount, 2) .
                  " added to your account. New balance: <strong>$" . number_format($me['balance'], 2) . "</strong>";
    }
}

$vouchers     = db()->query("SELECT * FROM vouchers ORDER BY id")->fetchAll();
$my_redeemed  = db()->query("SELECT * FROM vouchers WHERE used_by = $uid")->fetchAll();
?>

<div class="row justify-content-center">
  <div class="col-md-7">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-362 Race Condition</span>
      <span class="badge-vuln">CWE-840 Non-Atomic Redeem</span>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Redeem Voucher Code</div>
      <div class="card-body">
        <?php if ($error):  ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($result): ?><div class="alert alert-success"><?= $result ?></div><?php endif; ?>

        <div class="mb-3 p-2 bg-light rounded">
          Balance: <strong>$<?= number_format($me['balance'], 2) ?></strong>
        </div>

        <form method="POST">
          <div class="input-group mb-2">
            <input type="text" name="code" class="form-control text-uppercase"
                   placeholder="e.g. SAVE100"
                   value="<?= htmlspecialchars($_POST['code'] ?? '') ?>">
            <button class="btn btn-success">Redeem</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Available Vouchers (for demo)</div>
      <div class="table-responsive">
        <table class="table table-sm mb-0">
          <thead><tr><th>Code</th><th>Discount</th><th>Used?</th><th>Used By</th></tr></thead>
          <tbody>
          <?php foreach ($vouchers as $v): ?>
          <tr class="<?= $v['used'] ? 'table-secondary' : '' ?>">
            <td><code><?= $v['code'] ?></code></td>
            <td>$<?= number_format($v['discount'], 2) ?></td>
            <td><?= $v['used'] ? '✅ yes' : '❌ no' ?></td>
            <td><?= $v['used_by'] ? "user #" . $v['used_by'] : '-' ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card hint-card shadow-sm">
      <div class="card-body" style="font-size:.8rem">
        <strong>Race condition PoC (bash):</strong><br>
        <pre class="bg-dark text-light p-2 rounded mt-1" style="font-size:.75rem">for i in {1..20}; do
  curl -s -X POST http://localhost:8080/voucher.php \
    -b "PHPSESSID=YOUR_SESSION_ID" \
    -d "code=VIP200" &
done; wait</pre>
        Multiple concurrent requests pass the <code>used=0</code> check before any UPDATE commits.
        Result: voucher credited multiple times.<br><br>
        <strong>Fix:</strong> Use a DB transaction with <code>BEGIN EXCLUSIVE</code> or a single atomic
        <code>UPDATE ... WHERE used=0</code> and check rows affected.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
