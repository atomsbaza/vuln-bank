<?php
// ============================================================
//  VulnBank – PHP Type Juggling Auth Bypass
//  CWE-697: Incorrect Comparison
//  PHP's == operator coerces types:
//    - "0e123..." == "0e456..." → TRUE (both treated as 0^N = 0)
//    - 0 == "any non-numeric string" → TRUE
//    - TRUE == "any non-empty string" → TRUE
// ============================================================
require_once 'db.php';
require '_header.php';

$error = $success = '';
$demo_results = [];

// ── Magic hash demo ───────────────────────────────────────────
// These MD5 hashes all begin with 0e and are treated as 0^N = 0 by PHP ==
$magic_hashes = [
    'QNKCDZO'   => md5('QNKCDZO'),   // 0e830400451993494058024219903391
    '240610708'  => md5('240610708'), // 0e462097431906509019562988736854
    'aabg74wtg'  => md5('aabg74wtg'),// 0e176858761786647945966051875351
    'aabC9RqS'   => md5('aabC9RqS'), // 0e041022518165728065344349536299
];

// ── Vulnerable login using == ─────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {

    if ($_POST['action'] === 'login') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        $user = db()->query(
            "SELECT * FROM users WHERE username = '" . $username . "'"
        )->fetch();

        if ($user) {
            $input_hash = md5($password);
            // CWE-697: LOOSE COMPARISON == instead of ===
            // If stored hash is "0e462097..." and input hash is "0e830400..."
            // PHP evaluates: 0e... == 0e... → 0.0 == 0.0 → TRUE
            if ($user['password'] == $input_hash) {
                $success = "✅ Logged in as <strong>{$user['username']}</strong> (role: {$user['role']}) via type juggling!";
            } else {
                $error = "Login failed. Hash comparison: <code>{$user['password']}</code> == <code>{$input_hash}</code> → FALSE";
            }
        } else {
            $error = 'User not found.';
        }
    }

    if ($_POST['action'] === 'demo_compare') {
        $a = $_POST['val_a'] ?? '';
        $b = $_POST['val_b'] ?? '';
        $loose  = ($a == $b)  ? 'TRUE ✅' : 'FALSE ❌';
        $strict = ($a === $b) ? 'TRUE ✅' : 'FALSE ❌';
        $demo_results = compact('a','b','loose','strict');
    }
}
?>

<div class="row">
  <div class="col-md-5">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-697 Type Juggling</span> — <code>==</code> used instead of <code>===</code> for hash comparison
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Vulnerable Login (== comparison)</div>
      <div class="card-body">
        <?php if ($error):   ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="alert alert-success"><?= $success ?></div><?php endif; ?>

        <form method="POST">
          <input type="hidden" name="action" value="login">
          <div class="form-group mb-2">
            <label>Username (try: <code>alice</code>)</label>
            <input type="text" name="username" class="form-control" value="alice">
          </div>
          <div class="form-group mb-3">
            <label>
              Password
              <span class="vuln-label">[try magic hash: QNKCDZO]</span>
            </label>
            <input type="text" name="password" class="form-control"
                   placeholder="Try: QNKCDZO or 240610708">
            <small class="text-muted">
              alice's stored hash: <code><?= md5('password123') ?></code><br>
              Starts with <code>0e</code>? <strong><?= str_starts_with(md5('password123'), '0e') ? 'Yes ✅' : 'No ❌ — try another user' ?></strong>
            </small>
          </div>
          <button class="btn btn-danger w-100">Login with == comparison</button>
        </form>
      </div>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Live Comparison Demo</div>
      <div class="card-body">
        <form method="POST">
          <input type="hidden" name="action" value="demo_compare">
          <div class="row">
            <div class="col">
              <input type="text" name="val_a" class="form-control" placeholder="Value A"
                     value="<?= htmlspecialchars($_POST['val_a'] ?? '0e462097431906509019562988736854') ?>">
            </div>
            <div class="col">
              <input type="text" name="val_b" class="form-control" placeholder="Value B"
                     value="<?= htmlspecialchars($_POST['val_b'] ?? '0e830400451993494058024219903391') ?>">
            </div>
          </div>
          <button class="btn btn-sm btn-secondary mt-2 w-100">Compare</button>
        </form>
        <?php if ($demo_results): ?>
        <div class="mt-2 p-2 bg-light rounded" style="font-size:.85rem">
          <code><?= htmlspecialchars($demo_results['a']) ?></code><br>
          vs<br>
          <code><?= htmlspecialchars($demo_results['b']) ?></code><br><br>
          <strong>==  (loose):</strong> <?= $demo_results['loose'] ?><br>
          <strong>=== (strict):</strong> <?= $demo_results['strict'] ?>
        </div>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <div class="col-md-7">
    <div class="card shadow">
      <div class="card-header">Known Magic MD5 Hashes (all equal under ==)</div>
      <div class="table-responsive">
        <table class="table table-sm mb-0">
          <thead><tr><th>Input</th><th>MD5 Hash</th><th>== any other 0e hash?</th></tr></thead>
          <tbody>
          <?php foreach ($magic_hashes as $input => $hash): ?>
          <tr>
            <td><code><?= $input ?></code></td>
            <td><code style="font-size:.75rem"><?= $hash ?></code></td>
            <td><?= str_starts_with($hash, '0e') ? '<span class="text-success">YES ✅</span>' : '<span class="text-danger">NO</span>' ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body" style="font-size:.82rem">
        <strong>How it works:</strong><br>
        PHP's <code>==</code> casts strings starting with <code>0e</code> followed by digits to scientific notation floats: <code>0×10^N = 0</code>.<br>
        So <code>"0e1234" == "0e5678"</code> → <code>0.0 == 0.0</code> → <code>TRUE</code>.<br><br>
        <strong>Attack:</strong> Find any password whose MD5 starts with <code>0e[digits]</code>. If the victim's stored hash also starts with <code>0e[digits]</code>, the loose comparison passes.<br><br>
        <strong>Other juggling:</strong><br>
        <code>0 == "admin"</code> → TRUE (0 equals any non-numeric string)<br>
        <code>TRUE == "anything"</code> → TRUE<br>
        <code>"1" == "01"</code> → TRUE<br>
        <code>"100" == "1e2"</code> → TRUE (scientific notation)
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
