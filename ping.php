<?php
// ============================================================
//  VulnBank – Network Diagnostic Tool
//  INTENTIONAL VULNERABILITIES:
//    A03 – Command injection via unsanitised $host in shell_exec()
//    A05 – Tool accessible to any authenticated user
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$output = '';
$cmd_shown = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $host = $_POST['host'] ?? '';

    // A03: COMMAND INJECTION
    // $host goes directly into shell_exec() with no sanitisation.
    //
    // Payloads:
    //   127.0.0.1; id
    //   127.0.0.1 && cat /etc/passwd
    //   127.0.0.1 | ls -la /Users/pisitkoolplukpol/Work/vuln-bank/
    //   127.0.0.1; cat .env
    //   127.0.0.1 `whoami`
    //   $(cat /etc/passwd)
    $cmd_shown = "ping -c 3 " . $host;
    $output    = shell_exec($cmd_shown . " 2>&1");

    // A09: command and output not logged
}
?>

<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A03 Command Injection</span> — <code>$host</code> concatenated directly into <code>shell_exec()</code>
    </div>

    <div class="card shadow">
      <div class="card-header">Network Diagnostic – Ping</div>
      <div class="card-body">
        <form method="POST">
          <div class="form-group mb-3">
            <label>Host / IP
              <span class="vuln-label">[try: 127.0.0.1; id   or   127.0.0.1 && cat .env]</span>
            </label>
            <input type="text" name="host" class="form-control"
                   value="<?= htmlspecialchars($_POST['host'] ?? '') ?>"
                   placeholder="e.g. 127.0.0.1; cat /etc/passwd">
          </div>
          <button class="btn btn-primary">Run Ping</button>
        </form>

        <?php if ($output !== ''): ?>
        <hr>
        <p class="mb-1"><strong>Command executed:</strong> <code><?= htmlspecialchars($cmd_shown) ?></code></p>
        <pre class="bg-dark text-light p-3 rounded mt-2" style="max-height:400px;overflow:auto;font-size:.82rem"><?= htmlspecialchars($output) ?></pre>
        <?php endif; ?>
      </div>
    </div>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>Command injection payloads:</strong><br>
        <code>127.0.0.1; id</code><br>
        <code>127.0.0.1 && cat /etc/passwd</code><br>
        <code>127.0.0.1 | ls -la</code><br>
        <code>127.0.0.1; cat /Users/pisitkoolplukpol/Work/vuln-bank/.env</code><br>
        <code>$(whoami)</code> (subshell injection)
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
