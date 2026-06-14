<?php
// ============================================================
//  VulnBank – Loan Calculator
//  CWE-190: Integer Overflow on large loan amounts
//  CWE-681: Float rounding / Salami attack accumulation
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$uid    = (int)$_SESSION['user_id'];
$me     = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();
$result = $error = '';
$breakdown = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // ── Integer Overflow Demo ─────────────────────────────────
    if ($action === 'loan') {
        $total_raw = $_POST['total']  ?? '0';
        $months    = $_POST['months'] ?? '12';

        // CWE-190: INTEGER OVERFLOW
        // (int) cast of a huge string silently wraps or returns PHP_INT_MAX
        // PHP_INT_MAX = 9223372036854775807 on 64-bit
        // Supplying 9999999999999999999 → cast overflows to negative
        $total  = (int)$total_raw;   // ← VULNERABILITY: silent overflow
        $months = max(1, (int)$months);

        // If $total overflowed to negative, monthly payment is negative!
        $monthly = $total / $months;

        // Insert the loan with the overflowed values
        db()->prepare("INSERT INTO loans (user_id, amount, months, monthly) VALUES (?,?,?,?)")
             ->execute([$uid, $total, $months, $monthly]);

        // Update balance — negative monthly means bank PAYS the borrower
        db()->exec("UPDATE users SET balance = balance - ($monthly * $months) WHERE id = $uid");
        $me = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();

        $breakdown = [
            'input_raw'  => $total_raw,
            'after_cast' => $total,
            'php_int_max'=> PHP_INT_MAX,
            'overflowed' => $total < 0 || $total_raw > (string)PHP_INT_MAX,
            'monthly'    => $monthly,
        ];
        $result = $monthly < 0
            ? "🎉 Loan approved! Monthly payment: <strong style='color:green'>$" . number_format($monthly, 2) . "</strong> (bank pays YOU due to overflow!)"
            : "Loan approved. Monthly payment: $" . number_format($monthly, 2);
    }

    // ── Float Salami Attack Demo ──────────────────────────────
    if ($action === 'salami') {
        $iterations = min((int)($_POST['iterations'] ?? 100), 10000);
        $per_tx     = (float)($_POST['per_tx'] ?? 0.001);
        $accumulated = 0.0;
        $lost        = 0.0;

        for ($i = 0; $i < $iterations; $i++) {
            // CWE-681: Float precision loss
            // Each transaction rounds DOWN to 2 decimal places
            // The truncated sub-cent remainder is lost but could be harvested
            $raw       = $per_tx * 1.015; // 1.5% fee
            $rounded   = floor($raw * 100) / 100;   // round DOWN (bank keeps difference)
            $remainder = $raw - $rounded;
            $accumulated += $rounded;
            $lost        += $remainder;
        }

        $breakdown = [
            'iterations'   => $iterations,
            'per_tx'       => $per_tx,
            'total_rounded'=> $accumulated,
            'total_lost'   => $lost,
            'php_float'    => sprintf('%.20f', 0.1 + 0.2),  // classic float demo
        ];
        $result = "After $iterations transactions: accumulated = $" . number_format($accumulated, 6) .
                  " | Rounding remainder (salami) = <strong>$" . number_format($lost, 8) . "</strong>";
    }
}

$my_loans = db()->query("SELECT * FROM loans WHERE user_id = $uid ORDER BY created_at DESC")->fetchAll();
?>

<div class="row">
  <div class="col-md-6">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-190 Integer Overflow</span>
      <span class="badge-vuln">CWE-681 Float Salami</span>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Loan Application <span class="vuln-label">[CWE-190: overflow on (int) cast]</span></div>
      <div class="card-body">
        <?php if ($result): ?><div class="alert alert-info"><?= $result ?></div><?php endif; ?>

        <div class="mb-2 p-2 bg-light rounded" style="font-size:.82rem">
          Balance: <strong>$<?= number_format($me['balance'], 2) ?></strong>
        </div>

        <form method="POST">
          <input type="hidden" name="action" value="loan">
          <div class="row mb-2">
            <div class="col">
              <label>Total Amount
                <span class="vuln-label">[try: 99999999999999999999]</span>
              </label>
              <input type="text" name="total" class="form-control"
                     value="<?= htmlspecialchars($_POST['total'] ?? '10000') ?>">
            </div>
            <div class="col">
              <label>Months</label>
              <input type="number" name="months" class="form-control" value="12" min="1">
            </div>
          </div>

          <?php if ($breakdown && isset($breakdown['after_cast'])): ?>
          <div class="p-2 bg-dark text-light rounded mb-2" style="font-size:.78rem">
            Input string: <code><?= htmlspecialchars($breakdown['input_raw']) ?></code><br>
            After (int) cast: <code><?= $breakdown['after_cast'] ?></code>
            <?php if ($breakdown['overflowed']): ?><span class="text-warning"> ← OVERFLOW!</span><?php endif; ?><br>
            PHP_INT_MAX: <code><?= $breakdown['php_int_max'] ?></code><br>
            Monthly payment: <code><?= number_format($breakdown['monthly'], 2) ?></code>
          </div>
          <?php endif; ?>

          <button class="btn btn-danger w-100">Apply for Loan</button>
        </form>
      </div>
    </div>
  </div>

  <div class="col-md-6">
    <div class="card shadow mb-3">
      <div class="card-header">Salami Attack Simulator <span class="vuln-label">[CWE-681: float rounding]</span></div>
      <div class="card-body">
        <form method="POST">
          <input type="hidden" name="action" value="salami">
          <div class="row mb-2">
            <div class="col">
              <label>Transactions</label>
              <input type="number" name="iterations" class="form-control" value="1000">
            </div>
            <div class="col">
              <label>Amount Each ($)</label>
              <input type="number" name="per_tx" class="form-control" value="0.001" step="0.0001">
            </div>
          </div>
          <button class="btn btn-warning w-100">Run Salami Simulation</button>
        </form>

        <?php if ($result && isset($breakdown['iterations'])): ?>
        <div class="mt-2 p-2 bg-light rounded" style="font-size:.82rem">
          <?= $result ?><br>
          <span class="text-muted">Classic PHP float: 0.1 + 0.2 = <code><?= $breakdown['php_float'] ?></code></span>
        </div>
        <?php endif; ?>
      </div>
    </div>

    <?php if ($my_loans): ?>
    <div class="card shadow">
      <div class="card-header">My Loans</div>
      <div class="table-responsive">
        <table class="table table-sm mb-0">
          <thead><tr><th>Amount</th><th>Months</th><th>Monthly</th><th>Date</th></tr></thead>
          <tbody>
          <?php foreach ($my_loans as $l): ?>
          <tr class="<?= $l['monthly'] < 0 ? 'table-success' : '' ?>">
            <td>$<?= number_format($l['amount'], 2) ?></td>
            <td><?= $l['months'] ?></td>
            <td class="<?= $l['monthly'] < 0 ? 'text-success fw-bold' : '' ?>">$<?= number_format($l['monthly'], 2) ?></td>
            <td style="font-size:.8rem"><?= $l['created_at'] ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
    <?php endif; ?>
  </div>
</div>

<?php require '_footer.php'; ?>
