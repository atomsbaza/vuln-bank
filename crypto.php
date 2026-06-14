<?php
// ============================================================
//  VulnBank – Cryptography Showcase (broken crypto demos)
//  CWE-327: AES-ECB mode encryption
//  CWE-649: CBC padding oracle
//  CWE-330: Weak PRNG for CSRF token (mt_rand)
//  CWE-916: bcrypt with cost=4 (insufficient work factor)
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

// CWE-330: CSRF token generated with mt_rand — NOT cryptographically secure
// mt_rand state can be recovered after seeing ~2 outputs (php_mt_seed tool)
$csrf_token = md5(mt_rand()); // vulnerable PRNG

$ecb_key  = 'VulnBankKey12345'; // 16 bytes
$cbc_key  = 'VulnBankCBC12345'; // 16 bytes
$cbc_iv   = '0000000000000000'; // static IV — another vuln

$ecb_output = $cbc_output = $decrypt_output = $padding_oracle_response = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // ── AES-ECB encrypt ──────────────────────────────────────
    if ($action === 'ecb_encrypt') {
        $plaintext = $_POST['plaintext'] ?? '';
        // CWE-327: ECB mode — identical 16-byte blocks produce identical ciphertext
        // Reveals patterns; blocks can be rearranged to forge new ciphertexts
        $ecb_output = bin2hex(openssl_encrypt($plaintext, 'AES-128-ECB', $ecb_key, OPENSSL_RAW_DATA));
    }

    // ── AES-CBC encrypt ──────────────────────────────────────
    if ($action === 'cbc_encrypt') {
        $plaintext = $_POST['plaintext'] ?? '';
        // Static IV means: same plaintext → same first ciphertext block always
        $enc = openssl_encrypt($plaintext, 'AES-128-CBC', $cbc_key, OPENSSL_RAW_DATA, $cbc_iv);
        $cbc_output = base64_encode($enc);
    }

    // ── Padding oracle: decrypt + reveal padding validity ────
    if ($action === 'cbc_decrypt') {
        $ciphertext = base64_decode($_POST['ciphertext'] ?? '');
        // CWE-649: PADDING ORACLE — returns different responses for:
        //   padding error   → "Invalid padding"  (status 500)
        //   padding ok      → "Invalid data"     (status 200)
        // Attacker sends modified ciphertext blocks; observes which error appears
        // → recovers plaintext one byte at a time (e.g. with padbuster tool)
        $decrypted = @openssl_decrypt($ciphertext, 'AES-128-CBC', $cbc_key, OPENSSL_RAW_DATA, $cbc_iv);
        if ($decrypted === false) {
            // CWE-649: distinguishable padding error
            $padding_oracle_response = '❌ PKCS7 padding error — byte manipulation detected';
        } else {
            $padding_oracle_response = '✅ Valid padding — decrypted: ' . htmlspecialchars($decrypted);
        }
    }
}

// CWE-916: bcrypt with dangerously low cost factor
$weak_bcrypt = password_hash('password', PASSWORD_BCRYPT, ['cost' => 4]);
$ok_bcrypt   = password_hash('password', PASSWORD_BCRYPT, ['cost' => 12]);
?>

<div class="row">
  <div class="col-md-6">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-327 AES-ECB</span>
      <span class="badge-vuln">CWE-649 Padding Oracle</span>
      <span class="badge-vuln">CWE-330 mt_rand CSRF</span>
      <span class="badge-vuln">CWE-916 bcrypt cost=4</span>
    </div>

    <!-- AES-ECB -->
    <div class="card shadow mb-3">
      <div class="card-header">AES-ECB Encryption <span class="vuln-label">[CWE-327: reveals patterns]</span></div>
      <div class="card-body">
        <form method="POST">
          <input type="hidden" name="action" value="ecb_encrypt">
          <div class="form-group mb-2">
            <label>Plaintext (try 32+ chars with repeated 16-byte blocks)</label>
            <input type="text" name="plaintext" class="form-control"
                   value="<?= htmlspecialchars($_POST['plaintext'] ?? 'AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA') ?>">
            <small class="text-muted">Identical 16-byte blocks → identical ciphertext blocks in ECB</small>
          </div>
          <button class="btn btn-warning btn-sm">Encrypt (ECB)</button>
        </form>
        <?php if ($ecb_output): ?>
        <div class="mt-2 p-2 bg-dark text-warning rounded font-monospace" style="font-size:.78rem;word-break:break-all">
          <?= $ecb_output ?>
        </div>
        <?php endif; ?>
      </div>
    </div>

    <!-- CBC Padding Oracle -->
    <div class="card shadow mb-3">
      <div class="card-header">CBC Padding Oracle <span class="vuln-label">[CWE-649: distinguishable errors]</span></div>
      <div class="card-body">
        <form method="POST" class="mb-2">
          <input type="hidden" name="action" value="cbc_encrypt">
          <div class="input-group">
            <input type="text" name="plaintext" class="form-control" placeholder="Encrypt first..."
                   value="<?= htmlspecialchars($_POST['plaintext'] ?? 'account=VB-0001001') ?>">
            <button class="btn btn-outline-secondary btn-sm">Encrypt (CBC)</button>
          </div>
        </form>
        <?php if ($cbc_output): ?>
        <div class="mb-2 p-1 bg-light rounded" style="font-size:.78rem;word-break:break-all">Ciphertext: <code><?= $cbc_output ?></code></div>
        <?php endif; ?>
        <form method="POST">
          <input type="hidden" name="action" value="cbc_decrypt">
          <div class="input-group">
            <input type="text" name="ciphertext" class="form-control"
                   placeholder="Paste base64 ciphertext (modify a byte to test oracle)"
                   value="<?= htmlspecialchars($_POST['ciphertext'] ?? $cbc_output) ?>">
            <button class="btn btn-outline-danger btn-sm">Decrypt</button>
          </div>
        </form>
        <?php if ($padding_oracle_response): ?>
        <div class="mt-2 alert <?= str_starts_with($padding_oracle_response,'✅') ? 'alert-success' : 'alert-danger' ?> py-1" style="font-size:.82rem">
          <?= $padding_oracle_response ?>
        </div>
        <?php endif; ?>
        <small class="text-muted">Tool: <code>padbuster http://localhost:8080/crypto.php "&lt;ciphertext&gt;" 16</code></small>
      </div>
    </div>
  </div>

  <div class="col-md-6">
    <!-- Weak bcrypt -->
    <div class="card shadow mb-3">
      <div class="card-header">bcrypt Cost Factor <span class="vuln-label">[CWE-916: cost=4 too low]</span></div>
      <div class="card-body" style="font-size:.82rem">
        <p>Cost 4 (crackable in seconds):<br><code style="font-size:.72rem;word-break:break-all"><?= $weak_bcrypt ?></code></p>
        <p>Cost 12 (recommended):<br><code style="font-size:.72rem;word-break:break-all"><?= $ok_bcrypt ?></code></p>
        <p class="mb-0 text-muted">Cost 4 = ~1ms/hash; hashcat can try millions/sec. Cost 12 = ~250ms/hash.</p>
      </div>
    </div>

    <!-- Weak PRNG CSRF -->
    <div class="card shadow mb-3">
      <div class="card-header">Weak PRNG CSRF Token <span class="vuln-label">[CWE-330: mt_rand]</span></div>
      <div class="card-body" style="font-size:.82rem">
        <p>CSRF token generated with <code>md5(mt_rand())</code>:</p>
        <code class="d-block mb-2"><?= $csrf_token ?></code>
        <p class="mb-0 text-muted"><code>mt_rand()</code> uses a 32-bit seed. After observing 2 outputs, <code>php_mt_seed</code> can recover the full MT state and predict all future tokens.<br>
        <a href="https://www.openwall.com/php_mt_seed/" target="_blank">php_mt_seed tool →</a></p>
      </div>
    </div>

    <!-- Static IV -->
    <div class="card shadow hint-card">
      <div class="card-header">Additional Crypto Issues</div>
      <div class="card-body" style="font-size:.82rem">
        <ul class="mb-0">
          <li><strong>Static CBC IV:</strong> <code><?= $cbc_iv ?></code> — same plaintext prefix always produces same ciphertext block. Enables chosen-plaintext attacks.</li>
          <li><strong>Hardcoded key:</strong> <code><?= $ecb_key ?></code> in source code (A02).</li>
          <li><strong>No MAC:</strong> CBC ciphertext has no HMAC → malleable; attacker can flip plaintext bits by modifying the previous ciphertext block.</li>
          <li><strong>Timing attack:</strong> <code>$sig !== $expected</code> uses PHP's <code>!==</code> which short-circuits → timing oracle. Use <code>hash_equals()</code> instead.</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
