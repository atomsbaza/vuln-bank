<?php
// ============================================================
//  VulnBank – Dynamic Page Loader
//  CWE-98:  PHP Remote/Local File Inclusion via include()
//  CWE-22:  php://filter chain for source disclosure
//  CWE-626: Null byte injection (%00) to strip appended extension
//
//  Payloads:
//    php://filter/convert.base64-encode/resource=db       → base64 of db.php
//    php://filter/read=string.rot13/resource=config       → ROT13 of config.php
//    ../../etc/passwd%00                                  → strip ".php" (old PHP)
//    php://input                                          → execute POST body as PHP
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$output = $error = '';
$page   = $_GET['page'] ?? 'home';

// "Safe" pages whitelist attempt (bypassable)
$safe_pages = ['home', 'faq', 'terms', 'about'];

// Incomplete protection — only checks if $page is in the safe list
// but also allows php:// wrappers and doesn't block directory traversal
$is_safe = in_array($page, $safe_pages);

if (!$is_safe) {
    // Try to load it anyway with a .php extension appended
    // CWE-626: Null byte %00 strips the .php suffix in PHP < 5.3.4
    // CWE-98: php://filter bypasses the extension append
    $include_path = $page . '.php';
} else {
    $include_path = $page . '.php';
}

// Capture include output
ob_start();
try {
    // CWE-22/CWE-98: $page is user-controlled, directly included
    // php://filter/convert.base64-encode/resource=db → reads db.php as base64
    // php://input → executes POST body as PHP code
    @include($include_path);
} catch (Throwable $e) {
    echo 'Include error: ' . $e->getMessage(); // A05: raw error
}
$output = ob_get_clean();

// If the include produced no output but it's a filter resource, read directly
if ($output === '' && str_starts_with($page, 'php://')) {
    $output = file_get_contents($page);
}
?>

<div class="row justify-content-center">
  <div class="col-md-9">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-98 LFI/RFI</span>
      <span class="badge-vuln">CWE-22 php://filter</span>
      <span class="badge-vuln">CWE-626 Null Byte</span>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Dynamic Page Loader</div>
      <div class="card-body">
        <p class="text-muted">Navigate to a page using the <code>?page=</code> parameter.</p>
        <div class="d-flex gap-2 mb-3" style="gap:6px;flex-wrap:wrap">
          <a href="lfi.php?page=home"  class="btn btn-sm btn-outline-secondary">home</a>
          <a href="lfi.php?page=faq"   class="btn btn-sm btn-outline-secondary">faq</a>
          <a href="lfi.php?page=terms" class="btn btn-sm btn-outline-secondary">terms</a>
          <a href="lfi.php?page=php://filter/convert.base64-encode/resource=db"
             class="btn btn-sm btn-outline-danger">php://filter → db.php source</a>
          <a href="lfi.php?page=php://filter/convert.base64-encode/resource=config"
             class="btn btn-sm btn-outline-danger">php://filter → config.php</a>
          <a href="lfi.php?page=php://filter/convert.base64-encode/resource=.env"
             class="btn btn-sm btn-outline-danger">php://filter → .env</a>
        </div>

        <p><strong>Current page:</strong> <code><?= htmlspecialchars($page) ?></code>
           → include path: <code><?= htmlspecialchars($include_path) ?></code></p>

        <?php if ($output !== ''): ?>
        <div class="border rounded p-3 bg-light" style="max-height:400px;overflow:auto">
          <?php if (str_contains($page, 'base64-encode')): ?>
            <p class="text-muted" style="font-size:.8rem">Base64 output (decode with <code>base64 -d</code>):</p>
            <pre style="font-size:.75rem;word-break:break-all"><?= htmlspecialchars($output) ?></pre>
          <?php else: ?>
            <?= $output ?>
          <?php endif; ?>
        </div>
        <?php else: ?>
        <div class="text-muted">Page "<?= htmlspecialchars($page) ?>" produced no output (file may not exist).</div>
        <?php endif; ?>
      </div>
    </div>

    <div class="card hint-card shadow-sm">
      <div class="card-body" style="font-size:.8rem">
        <strong>LFI / php://filter payloads:</strong><br>
        <code>?page=php://filter/convert.base64-encode/resource=db</code> → db.php source (base64)<br>
        <code>?page=php://filter/convert.base64-encode/resource=../../../etc/passwd</code> → /etc/passwd<br>
        <code>?page=php://filter/read=string.rot13/resource=index</code> → ROT13 encoded source<br>
        <code>?page=php://input</code> (POST body = PHP code) → RCE<br>
        <code>?page=../../etc/passwd%00</code> → null byte strips ".php" (PHP &lt; 5.3.4)<br><br>
        <strong>Decode base64 output:</strong> <code>echo "&lt;output&gt;" | base64 -d</code>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
