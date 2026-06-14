<?php
// ============================================================
//  A05: Security Misconfiguration
//  phpinfo() exposed on a publicly accessible URL.
//  Reveals: PHP version, loaded extensions, INI settings,
//           environment variables, file paths, server info.
//  An attacker can fingerprint the exact stack for targeted exploits.
// ============================================================
phpinfo();
