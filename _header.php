<?php if (session_status() === PHP_SESSION_NONE) session_start(); ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnBank – Secure Banking You Can Trust</title>
<!-- A06: Bootstrap 4.0.0-alpha.6 – multiple known XSS CVEs in this version -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css"
      integrity="" crossorigin="anonymous">
<!-- A06: jQuery 1.12.4 – CVE-2019-11358 prototype pollution, CVE-2020-11022/23 XSS -->
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<link rel="stylesheet" href="assets/style.css">
<!-- A05: Version info in meta – helps fingerprint the stack -->
<meta name="generator" content="VulnBank v1.0 / PHP <?= PHP_VERSION ?>">
</head>
<body>
<nav class="navbar navbar-toggleable-md navbar-inverse bg-primary">
  <a class="navbar-brand" href="dashboard.php">🏦 VulnBank</a>
  <?php if (isset($_SESSION['user_id'])): ?>
  <div class="ml-auto d-flex gap-1" style="gap:6px">
    <a href="dashboard.php"   class="btn btn-outline-light btn-sm">Dashboard</a>
    <a href="transfer.php"    class="btn btn-outline-light btn-sm">Transfer</a>
    <a href="export.php"      class="btn btn-outline-light btn-sm">Export/Import</a>
    <a href="upload.php"      class="btn btn-outline-light btn-sm">Upload</a>
    <a href="ping.php"        class="btn btn-outline-light btn-sm">Ping</a>
    <a href="eval.php"        class="btn btn-outline-light btn-sm">Templates</a>
    <a href="profile.php"     class="btn btn-outline-light btn-sm">Profile</a>
    <a href="search.php"      class="btn btn-outline-light btn-sm">Search</a>
    <a href="api.php"         class="btn btn-outline-light btn-sm">API</a>
    <a href="hints.php"       class="btn btn-outline-warning btn-sm">💡 Hints</a>
    <a href="admin.php"       class="btn btn-outline-light btn-sm">Admin</a>
    <a href="logout.php"      class="btn btn-danger btn-sm">Logout</a>
  </div>
  <?php else: ?>
  <div class="ml-auto">
    <a href="index.php"    class="btn btn-outline-light btn-sm">Login</a>
    <a href="register.php" class="btn btn-outline-light btn-sm">Register</a>
    <a href="hints.php"    class="btn btn-outline-warning btn-sm">💡 Hints</a>
  </div>
  <?php endif; ?>
</nav>
<div class="container mt-4">
