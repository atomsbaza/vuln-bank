<?php
// ============================================================
//  VulnBank – Debug Endpoint (A05: Security Misconfiguration)
//  Left enabled in production. Dumps session, server, env,
//  cookies, and all defined constants. No auth check.
// ============================================================
require_once 'db.php';
if (session_status() === PHP_SESSION_NONE) session_start();

// A01: No authentication or IP restriction on a debug endpoint
// A05: Full environment exposure

header('Content-Type: text/html');
?>
<!DOCTYPE html>
<html>
<head>
  <title>VulnBank Debug</title>
  <style>
    body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
    h2   { color: #f14c4c; border-bottom: 1px solid #444; padding-bottom: 6px; }
    pre  { background: #252526; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: .8rem; }
    .warn { color: #ffd700; margin-bottom: 10px; }
  </style>
</head>
<body>
<p class="warn">⚠️ A05: DEBUG ENDPOINT EXPOSED IN PRODUCTION — no authentication required</p>

<h2>$_SESSION</h2>
<pre><?= htmlspecialchars(print_r($_SESSION, true)) ?></pre>

<h2>$_COOKIE</h2>
<pre><?= htmlspecialchars(print_r($_COOKIE, true)) ?></pre>

<h2>$_SERVER</h2>
<pre><?= htmlspecialchars(print_r($_SERVER, true)) ?></pre>

<h2>$_ENV</h2>
<pre><?= htmlspecialchars(print_r($_ENV, true)) ?></pre>

<h2>Defined Constants (APP_*)</h2>
<pre><?php
$consts = get_defined_constants(true);
echo htmlspecialchars(print_r(array_filter($consts['user'] ?? [], fn($k) => str_contains($k, 'APP_') || str_contains($k, 'DB_') || str_contains($k, 'SMTP'), ARRAY_FILTER_USE_KEY), true));
?></pre>

<h2>Database – All Users (including password hashes)</h2>
<pre><?php
try {
    $users = db()->query("SELECT * FROM users")->fetchAll(PDO::FETCH_ASSOC);
    echo htmlspecialchars(print_r($users, true));
} catch (Exception $e) {
    echo 'DB error: ' . htmlspecialchars($e->getMessage());
}
?></pre>

<h2>PHP Configuration (selected)</h2>
<pre><?php
$keys = ['allow_url_fopen','allow_url_include','disable_functions','display_errors',
         'error_reporting','file_uploads','upload_max_filesize','open_basedir',
         'session.cookie_httponly','session.cookie_secure','session.use_strict_mode'];
foreach ($keys as $k) {
    echo "$k = " . ini_get($k) . "\n";
}
?></pre>

<h2>.env file</h2>
<pre><?= htmlspecialchars(file_exists(__DIR__.'/.env') ? file_get_contents(__DIR__.'/.env') : 'not found') ?></pre>

</body>
</html>
