<?php
// ============================================================
//  VulnBank – Legacy Config File
//  A05: Accessible via /config.php — no auth, no restriction
//  A02: All credentials in plaintext
// ============================================================

// Database
define('LEGACY_DB_HOST', 'localhost');
define('LEGACY_DB_USER', 'vulnbank_app');
define('LEGACY_DB_PASS', 'Db@P4ssw0rd!2020');
define('LEGACY_DB_NAME', 'vulnbank');

// External payment gateway
define('PAYMENT_API_KEY',    'pk_live_vulnbank_51abc123def456');
define('PAYMENT_API_SECRET', 'sk_live_vulnbank_9f8e7d6c5b4a3');
define('PAYMENT_WEBHOOK',    'http://payments.vulnbank.local/webhook');

// SMS provider
define('SMS_API_KEY',  'sms_api_8f3a2c1d9e4b5f6a');
define('SMS_API_URL',  'https://sms.vulnbank.local/send');
define('SMS_SENDER',   'VULNBANK');

// Admin panel "security"
define('ADMIN_SECRET_URL', '/admin_9f3a2c1d.php'); // security by obscurity
define('ADMIN_IP_WHITELIST', '127.0.0.1,10.0.0.0/8'); // stored but never checked

// Encryption (never actually used)
define('CIPHER_KEY', '0000000000000000'); // 16 bytes of zeros
define('CIPHER_IV',  '0000000000000000');

// Session
define('SESSION_LIFETIME', 86400 * 365); // 1 year session timeout
define('REMEMBER_COOKIE_LIFETIME', 86400 * 365 * 10); // 10 year remember-me

if (php_sapi_name() !== 'cli') {
    // A05: Show config values when accessed via browser
    header('Content-Type: text/plain');
    foreach (get_defined_constants(true)['user'] as $k => $v) {
        echo "$k = $v\n";
    }
}
