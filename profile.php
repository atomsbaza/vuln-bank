<?php
// ============================================================
//  VulnBank – User Profile
//  INTENTIONAL VULNERABILITIES:
//    A03 – Stored XSS: bio & community message saved unescaped
//    A10 – SSRF: avatar URL fetched server-side without restriction
//    A08 – PHP unserialize() on a user-controlled cookie (object injection)
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$uid   = (int)$_SESSION['user_id'];
$me    = db()->query("SELECT * FROM users WHERE id = $uid")->fetch();
$error = $success = $ssrf_output = '';

// A08: PHP object injection via unserialize on user-controlled cookie
// Payload (PHP): O:8:"stdClass":1:{s:4:"name";s:5:"hacker";}
// With a custom gadget class this can achieve RCE
if (isset($_COOKIE['user_prefs'])) {
    // A08: Never deserialise user-controlled data
    $prefs = @unserialize(base64_decode($_COOKIE['user_prefs']));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // ── Update bio (stored XSS) ────────────────────────────
    if ($action === 'update_bio') {
        $bio = $_POST['bio'] ?? '';  // A03: not sanitised
        // A03: bio saved as-is → <script>alert('XSS')</script> stored in DB
        db()->prepare("UPDATE users SET bio = ? WHERE id = $uid")->execute([$bio]);
        $me['bio'] = $bio;
        $success = 'Profile updated.';
    }

    // ── Post community message (stored XSS) ───────────────
    elseif ($action === 'post_message') {
        $content = $_POST['content'] ?? ''; // A03: raw HTML/JS accepted
        db()->prepare(
            "INSERT INTO messages (user_id,username,content) VALUES (?,?,?)"
        )->execute([$uid, $me['username'], $content]);
        $success = 'Message posted. View it on the <a href="dashboard.php">Dashboard</a>.';
    }

    // ── Fetch avatar URL (SSRF) ────────────────────────────
    elseif ($action === 'update_avatar') {
        $url = trim($_POST['avatar_url'] ?? '');
        if ($url) {
            // A10: SSRF – fetches any URL server-side with no allowlist
            // Try: file:///etc/passwd
            //      file:///Users/pisitkoolplukpol/Work/vuln-bank/.env
            //      http://169.254.169.254/latest/meta-data/ (AWS metadata)
            //      http://localhost:8080/admin.php
            //      dict://localhost:11211/ (memcached)
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT        => 5,
                CURLOPT_SSL_VERIFYPEER => false, // A05: TLS verification disabled
            ]);
            $ssrf_output = curl_exec($ch);
            $curlErr     = curl_error($ch);
            curl_close($ch);

            if ($curlErr) {
                $error = "Fetch error: $curlErr";
            } else {
                db()->prepare("UPDATE users SET avatar_url = ? WHERE id = $uid")->execute([$url]);
                $me['avatar_url'] = $url;
                $success = 'Avatar URL saved and content fetched (shown below).';
            }
        }
    }
}
?>

<div class="row">
  <!-- ── Left: Profile ──────────────────────────────────── -->
  <div class="col-md-5">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A03 Stored XSS</span>
      <span class="badge-vuln">A10 SSRF</span>
      <span class="badge-vuln">A08 Unserialize</span>
    </div>

    <div class="card shadow mb-3">
      <div class="card-header bg-primary text-white">
        Profile – <?= htmlspecialchars($me['username']) ?>
      </div>
      <div class="card-body">
        <p><strong>Account:</strong> <?= $me['account_number'] ?></p>
        <p><strong>Role:</strong> <?= $me['role'] ?></p>
        <p><strong>Bio:</strong></p>
        <!-- A03: bio rendered without escaping → XSS fires here -->
        <div class="border rounded p-2 mb-3" style="min-height:40px"><?= $me['bio'] ?></div>

        <?php if ($error):   ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="alert alert-success"><?= $success ?></div><?php endif; ?>

        <!-- Bio update form (stored XSS) -->
        <form method="POST">
          <input type="hidden" name="action" value="update_bio">
          <div class="form-group mb-2">
            <label>Update Bio
              <span class="vuln-label">[A03: try &lt;script&gt;alert(1)&lt;/script&gt;]</span>
            </label>
            <textarea name="bio" class="form-control" rows="3"
                      placeholder="<script>alert('XSS')</script>"><?= $me['bio'] ?></textarea>
          </div>
          <button class="btn btn-primary btn-sm w-100">Save Bio</button>
        </form>
      </div>
    </div>

    <!-- Community message (stored XSS) -->
    <div class="card shadow mb-3">
      <div class="card-header">Post to Community Board</div>
      <div class="card-body">
        <form method="POST">
          <input type="hidden" name="action" value="post_message">
          <div class="form-group mb-2">
            <label>Message
              <span class="vuln-label">[A03: HTML/JS accepted as-is]</span>
            </label>
            <textarea name="content" class="form-control" rows="3"
              placeholder="<img src=x onerror=alert('XSS')>"></textarea>
          </div>
          <button class="btn btn-secondary btn-sm w-100">Post Message</button>
        </form>
      </div>
    </div>
  </div>

  <!-- ── Right: SSRF ────────────────────────────────────── -->
  <div class="col-md-7">
    <div class="card shadow mb-3">
      <div class="card-header">
        Avatar URL Fetch
        <span class="vuln-label">[A10: SSRF – any URL fetched server-side]</span>
      </div>
      <div class="card-body">
        <form method="POST">
          <input type="hidden" name="action" value="update_avatar">
          <div class="form-group mb-2">
            <label>Avatar URL</label>
            <input type="text" name="avatar_url" class="form-control"
                   value="<?= htmlspecialchars($me['avatar_url']) ?>"
                   placeholder="https://example.com/photo.jpg">
            <small class="text-muted">
              SSRF payloads:<br>
              <code>file:///etc/passwd</code><br>
              <code>file:///Users/pisitkoolplukpol/Work/vuln-bank/.env</code><br>
              <code>http://169.254.169.254/latest/meta-data/</code><br>
              <code>http://localhost:8080/admin.php</code>
            </small>
          </div>
          <button class="btn btn-info btn-sm w-100">Fetch &amp; Save</button>
        </form>

        <?php if ($ssrf_output !== ''): ?>
        <hr>
        <div class="mt-2">
          <strong>Server-side fetch result:</strong>
          <pre class="bg-dark text-light p-3 rounded mt-2" style="max-height:300px;overflow:auto;font-size:.78rem"><?= htmlspecialchars(substr($ssrf_output, 0, 4096)) ?></pre>
        </div>
        <?php endif; ?>
      </div>
    </div>

    <div class="card shadow hint-card">
      <div class="card-header">A08 – PHP Object Injection</div>
      <div class="card-body" style="font-size:.82rem">
        <p>A <code>user_prefs</code> cookie is deserialized on each page load:</p>
        <pre class="bg-dark text-light p-2 rounded">$prefs = unserialize(base64_decode($_COOKIE['user_prefs']));</pre>
        <p>Set the cookie in DevTools:</p>
        <pre class="bg-dark text-light p-2 rounded">document.cookie = "user_prefs=" + btoa('O:8:"stdClass":1:{s:4:"test";s:3:"pwn";}');</pre>
        <p class="mb-0">With a suitable POP gadget chain this can achieve RCE.</p>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
