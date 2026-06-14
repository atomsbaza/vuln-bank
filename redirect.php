<?php
// ============================================================
//  VulnBank – Outbound Link Handler
//  INTENTIONAL VULNERABILITIES:
//    A01 – Open redirect: ?url= accepts any destination with no validation
//    A07 – Can be used in phishing to steal credentials via redirect
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$url = $_GET['url'] ?? '';

// A01: OPEN REDIRECT
// No allowlist, no host check – redirects to any URL.
// Phishing PoC:
//   http://localhost:8080/redirect.php?url=http://evil.com/fake-vulnbank-login
//   http://localhost:8080/redirect.php?url=javascript:alert(document.cookie)
//   http://localhost:8080/redirect.php?url=//evil.com
//
// Common "defences" that are bypassable:
//   - strpos($url, 'http') !== false  → bypassed with //evil.com
//   - strpos($url, 'vulnbank') !== false → bypassed with http://evil.com?vulnbank=1

if ($url) {
    // A09: redirect not logged
    header("Location: $url");
    exit;
}

require '_header.php';
?>

<div class="row justify-content-center">
  <div class="col-md-7">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A01 Open Redirect</span> — <code>?url=</code> redirects to any destination with zero validation
    </div>

    <div class="card shadow">
      <div class="card-header">External Link Handler</div>
      <div class="card-body">
        <p class="text-muted">VulnBank routes external links through this page for "tracking" purposes.</p>

        <div class="form-group mb-3">
          <label>Test a redirect URL
            <span class="vuln-label">[A01: any URL works — no allowlist]</span>
          </label>
          <div class="input-group">
            <input type="text" id="rurl" class="form-control"
                   placeholder="http://evil.com/fake-login">
            <div class="input-group-append">
              <button class="btn btn-danger"
                      onclick="location.href='redirect.php?url='+encodeURIComponent(document.getElementById('rurl').value)">
                Redirect
              </button>
            </div>
          </div>
        </div>

        <p>Legitimate-looking links using this endpoint:</p>
        <ul>
          <li><a href="redirect.php?url=https://google.com">Terms &amp; Conditions</a></li>
          <li><a href="redirect.php?url=https://apple.com">Privacy Policy</a></li>
        </ul>
      </div>
    </div>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>Open redirect payloads:</strong><br>
        <code>redirect.php?url=http://evil.com/fake-login</code><br>
        <code>redirect.php?url=//evil.com</code> (protocol-relative)<br>
        <code>redirect.php?url=javascript:alert(document.cookie)</code><br>
        <strong>Phishing use:</strong> email victim a legitimate-looking vulnbank URL that redirects to a credential harvester.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
