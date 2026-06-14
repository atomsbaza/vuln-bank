<?php
// A07: Session not fully invalidated – session_destroy() called but
// the session ID is not regenerated and the cookie is not explicitly deleted.
// An attacker who captured the session token before logout may still replay it.
if (session_status() === PHP_SESSION_NONE) session_start();
$_SESSION = [];
session_destroy();
// A07: old session cookie remains in browser with same ID until browser closes
header('Location: index.php');
exit;
