<?php
// ============================================================
//  VulnBank – Statement Download
//  INTENTIONAL VULNERABILITIES:
//    A01 – Path traversal: ?file= reads any file on the system
//    A05 – No file-type restriction; no allowlist
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

// A01/A05: PATH TRAVERSAL
// ?file= is accepted without sanitisation or allowlist.
//
// Payloads:
//   download.php?file=../../../etc/passwd
//   download.php?file=.env
//   download.php?file=db.php
//   download.php?file=../../../Users/pisitkoolplukpol/.ssh/id_rsa
//   download.php?file=vulnbank.db   (raw SQLite dump)
//
// str_replace('../', '') is the "fix" that is trivially bypassed with:
//   ....//....//....//etc/passwd  (double-dot encoding bypass)

if (isset($_GET['file'])) {
    $file = $_GET['file'];

    // "Sanitisation" that is trivially bypassed
    // Try: ....//....//etc/passwd  or  ..%2F..%2Fetc%2Fpasswd
    $file = str_replace('../', '', $file);   // A01: incomplete defence – bypassable

    $path = __DIR__ . '/' . $file;

    if (file_exists($path) && is_file($path)) {
        // Serve the file with a generic content type (doesn't restrict PHP execution if uploaded)
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        readfile($path);
        exit;
    } else {
        // A05: full path disclosed in error message
        $error = "File not found: $path";
    }
}

require '_header.php';
?>

<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A01 Path Traversal</span> — <code>?file=</code> reads any accessible file; the <code>str_replace('../')</code> defence is bypassable
    </div>

    <div class="card shadow">
      <div class="card-header">Download Account Statement</div>
      <div class="card-body">
        <?php if (isset($error)): ?>
          <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <p>Download your monthly statements:</p>
        <ul>
          <li><a href="download.php?file=assets/style.css">June 2024 Statement (CSS)</a></li>
          <li><a href="download.php?file=assets/style.css">May 2024 Statement (CSS)</a></li>
        </ul>
        <hr>
        <div class="form-group">
          <label>Custom file path
            <span class="vuln-label">[A01: path traversal]</span>
          </label>
          <div class="input-group">
            <input type="text" id="fp" class="form-control"
                   placeholder="e.g. .env  or  ....//....//etc/passwd">
            <div class="input-group-append">
              <button class="btn btn-outline-secondary"
                      onclick="location.href='download.php?file='+document.getElementById('fp').value">
                Download
              </button>
            </div>
          </div>
          <small class="text-muted">
            Try: <code>.env</code> · <code>db.php</code> · <code>vulnbank.db</code> ·
            <code>....//....//etc/passwd</code>
          </small>
        </div>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
