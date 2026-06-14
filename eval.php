<?php
// ============================================================
//  VulnBank – Template / Report Engine
//  INTENTIONAL VULNERABILITIES:
//    A03 – Code injection: user input passed directly to eval()
//    A03 – Also demonstrates Server-Side Template Injection (SSTI)
//          if output is treated as a template
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$uid    = (int)$_SESSION['user_id'];
$me     = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();
$output = $error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $template = $_POST['template'] ?? '';

    // A03: CODE INJECTION via eval()
    // The template supports {{expr}} placeholders that are eval()'d.
    //
    // Benign use:   Hello {{$me['username']}}  →  Hello alice
    // Payloads:
    //   {{system('id')}}
    //   {{file_get_contents('.env')}}
    //   {{shell_exec('ls -la')}}
    //   {{passthru('cat /etc/passwd')}}
    //   {{var_export(get_defined_vars(), true)}}

    $rendered = preg_replace_callback('/\{\{(.+?)\}\}/s', function($m) use ($me, $uid) {
        $expr = trim($m[1]);
        try {
            ob_start();
            // A03: DIRECT eval() OF USER INPUT — arbitrary PHP execution
            $result = eval("return ($expr);");
            $extra  = ob_get_clean();
            return htmlspecialchars((string)($result ?? $extra));
        } catch (Throwable $e) {
            return '<span style="color:red">[eval error: ' . htmlspecialchars($e->getMessage()) . ']</span>';
        }
    }, $template);

    $output = $rendered;
}

$default_tpl = "Dear {{htmlspecialchars(\$me['username'])}},\n\nYour balance is \${{number_format(\$me['balance'], 2)}}.\n\nAccount: {{\$me['account_number']}}\n\nThank you for banking with VulnBank.";
?>

<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A03 Code Injection / SSTI</span> — <code>{{expr}}</code> placeholders are eval()'d as PHP
    </div>

    <div class="card shadow">
      <div class="card-header">Statement Template Engine</div>
      <div class="card-body">
        <form method="POST">
          <div class="form-group mb-3">
            <label>Template
              <span class="vuln-label">[try: {{system('id')}}  or  {{file_get_contents('.env')}}]</span>
            </label>
            <textarea name="template" class="form-control" rows="10"
                      style="font-family:monospace;font-size:.85rem"><?= htmlspecialchars($_POST['template'] ?? $default_tpl) ?></textarea>
            <small class="text-muted">Use <code>{{expr}}</code> for dynamic values. <code>$me</code> is the current user array.</small>
          </div>
          <button class="btn btn-primary">Render Template</button>
        </form>

        <?php if ($output !== ''): ?>
        <hr>
        <strong>Output:</strong>
        <div class="border rounded p-3 mt-2" style="white-space:pre-wrap;font-family:monospace;font-size:.85rem;background:#f8f9fa"><?= $output ?></div>
        <?php endif; ?>
      </div>
    </div>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>Code injection payloads:</strong><br>
        <code>{{system('id')}}</code><br>
        <code>{{file_get_contents('.env')}}</code><br>
        <code>{{shell_exec('ls -la')}}</code><br>
        <code>{{passthru('cat /etc/passwd')}}</code><br>
        <code>{{var_export($_SERVER, true)}}</code>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
