<?php
// ============================================================
//  VulnBank – extract() / parse_str() Variable Overwrite
//  CWE-915: Improperly Controlled Modification of Dynamically-
//           Determined Object Attributes
//
//  extract($_POST) imports ALL POST keys into the local symbol
//  table, overwriting any existing variable including auth flags.
//
//  Payloads:
//    POST: authorized=1          → bypass auth check
//    POST: role=admin            → elevate privilege
//    POST: amount=1&balance=9999 → overwrite balance variable
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$uid = (int)$_SESSION['user_id'];
$me  = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();

$result = $error = '';
$authorized = false;  // will be overwritten by extract() below
$role       = 'user'; // will be overwritten
$discount   = 0;      // will be overwritten

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // ── Demo 1: Auth bypass via extract() ────────────────────
    if ($action === 'wire') {
        $amount = (float)($_POST['amount'] ?? 0);
        $to     = $_POST['to'] ?? '';

        // CWE-915: extract() overwrites $authorized, $role, $discount
        // with whatever the attacker sends in POST body
        extract($_POST);   // ← VULNERABILITY

        // $authorized was false; if attacker POSTs authorized=1, it's now true
        if (!$authorized) {
            $error = 'High-value wire transfer requires 2FA authorization. Set <code>authorized=1</code> in the POST body.';
        } else {
            $result = "✅ Wire transfer of $" . number_format((float)$amount, 2) . " to <strong>" . htmlspecialchars((string)$to) . "</strong> authorized!<br>Role used: <strong>" . htmlspecialchars((string)$role) . "</strong>";
        }
    }

    // ── Demo 2: parse_str() variable overwrite ────────────────
    if ($action === 'promo') {
        $promo_code = $_POST['promo_code'] ?? '';
        $discount   = 0;

        // Simulate fetching discount for a promo code
        if ($promo_code === 'SUMMER10') $discount = 10;
        if ($promo_code === 'VIP50')    $discount = 50;

        // CWE-915: parse_str() on user input overwrites $discount
        // Attacker sends: extra=ignored&discount=100
        parse_str($_SERVER['QUERY_STRING'], $vars);
        extract($vars);  // ← VULNERABILITY: $discount can be overwritten via ?discount=100

        $result = "Promo code: <strong>" . htmlspecialchars($promo_code) . "</strong> | Discount applied: <strong>$" . (float)$discount . "</strong>";
    }
}
?>

<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-915 extract() overwrite</span> — POST keys overwrite local PHP variables including auth flags
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">High-Value Wire Transfer (requires authorization)</div>
      <div class="card-body">
        <?php if ($error):  ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($result): ?><div class="alert alert-success"><?= $result ?></div><?php endif; ?>

        <form method="POST">
          <input type="hidden" name="action" value="wire">
          <div class="row mb-2">
            <div class="col">
              <label>Amount</label>
              <input type="number" name="amount" class="form-control" value="50000">
            </div>
            <div class="col">
              <label>Destination Account</label>
              <input type="text" name="to" class="form-control" value="SWIFT-9988776655">
            </div>
          </div>
          <div class="form-group mb-3">
            <label>
              Extra POST fields
              <span class="vuln-label">[CWE-915: add authorized=1 to bypass the check]</span>
            </label>
            <input type="text" name="authorized" class="form-control"
                   placeholder="Set to 1 to bypass authorization check" value="1">
            <small class="text-muted">Also try: <code>role=admin</code></small>
          </div>
          <button class="btn btn-danger w-100">Submit Wire Transfer</button>
        </form>
      </div>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Promo Code (parse_str overwrite via query string)</div>
      <div class="card-body">
        <form method="POST" id="promoForm">
          <input type="hidden" name="action" value="promo">
          <div class="row mb-2">
            <div class="col">
              <label>Promo Code</label>
              <input type="text" name="promo_code" class="form-control" value="SUMMER10">
            </div>
          </div>
          <small class="text-muted mb-2 d-block">
            <span class="vuln-label">[CWE-915: append ?discount=999 to the URL to override the server-side discount]</span><br>
            Try submitting with URL: <code>extract.php?discount=999</code>
          </small>
          <button class="btn btn-primary"
                  onclick="this.form.action='extract.php?discount=999'">
            Apply Promo (inject discount via URL)
          </button>
        </form>
      </div>
    </div>

    <div class="card hint-card shadow-sm">
      <div class="card-body" style="font-size:.82rem">
        <strong>Vulnerable code pattern:</strong><br>
        <pre class="bg-dark text-light p-2 rounded mt-1 mb-1" style="font-size:.78rem">$authorized = false;
extract($_POST);        // overwrites $authorized with POST['authorized']
if (!$authorized) { /* BYPASSED */ }</pre>
        <strong>Fix:</strong> Never use <code>extract()</code> / <code>parse_str()</code> on user input.
        Explicitly read only the keys you expect: <code>$amount = $_POST['amount']</code>.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
