<?php
// ============================================================
//  VulnBank – JWT API Authentication
//  CWE-347: Improper Verification of Cryptographic Signature
//
//  VULNERABILITIES:
//    1. alg:none accepted — no signature required
//    2. HS256/RS256 confusion — app uses a known public key as HMAC secret
//    3. Weak secret: "secret" used for HMAC signing
//    4. No token expiry enforcement
//
//  Generate a valid token at /jwt_api.php?action=login
//  Then forge an admin token at /jwt_api.php?action=forge
// ============================================================
require_once 'db.php';
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// CWE-347: Weak HMAC secret
define('JWT_SECRET', 'secret');  // trivially guessable

// ── JWT helpers ───────────────────────────────────────────────
function b64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function b64url_decode(string $data): string {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

function jwt_sign(array $header, array $payload, string $secret): string {
    $h = b64url_encode(json_encode($header));
    $p = b64url_encode(json_encode($payload));
    $sig = b64url_encode(hash_hmac('sha256', "$h.$p", $secret, true));
    return "$h.$p.$sig";
}

function jwt_verify(string $token): array|false {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;

    [$h, $p, $sig] = $parts;
    $header  = json_decode(b64url_decode($h), true);
    $payload = json_decode(b64url_decode($p), true);

    $alg = $header['alg'] ?? 'none';

    // CWE-347: VULNERABILITY #1 — alg:none accepted without signature
    if ($alg === 'none' || $alg === '') {
        // No signature verification at all!
        return $payload;
    }

    // CWE-347: VULNERABILITY #2 — algorithm taken from token header
    // Attacker can switch RS256 → HS256 and sign with the public key
    if ($alg === 'HS256') {
        $expected = b64url_encode(hash_hmac('sha256', "$h.$p", JWT_SECRET, true));
        // CWE-347: simple string compare (also vulnerable to timing attack)
        if ($sig !== $expected) return false;
        return $payload;
    }

    return false;
}

// ── Endpoints ─────────────────────────────────────────────────
$action = $_GET['action'] ?? '';

if ($action === 'login') {
    // Issue a JWT for demo credentials
    $username = $_GET['user'] ?? 'alice';
    $user = db()->query("SELECT * FROM users WHERE username = '" . $username . "'")->fetch();
    if (!$user) {
        echo json_encode(['error' => 'User not found']);
        exit;
    }
    $token = jwt_sign(
        ['alg' => 'HS256', 'typ' => 'JWT'],
        ['sub' => $user['id'], 'username' => $user['username'], 'role' => $user['role'],
         'iat' => time(), 'exp' => time() + 3600]
        , JWT_SECRET
    );
    echo json_encode([
        'token' => $token,
        'hint'  => 'Decode at jwt.io. Change alg to "none", set role to "admin", remove signature.',
    ]);
    exit;
}

if ($action === 'forge') {
    // Show a pre-forged alg:none admin token
    $h = b64url_encode(json_encode(['alg' => 'none', 'typ' => 'JWT']));
    $p = b64url_encode(json_encode(['sub' => 1, 'username' => 'admin', 'role' => 'admin', 'iat' => time()]));
    $forged = "$h.$p.";  // empty signature
    echo json_encode([
        'forged_token' => $forged,
        'usage'        => 'curl -H "Authorization: Bearer ' . $forged . '" http://localhost:8080/jwt_api.php?action=me',
    ]);
    exit;
}

if ($action === 'me') {
    // Verify supplied JWT and return user data
    $auth  = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $token = str_replace('Bearer ', '', $auth);
    if (!$token) $token = $_GET['token'] ?? '';

    $payload = jwt_verify($token);
    if (!$payload) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid or missing JWT']);
        exit;
    }

    // Return full user record (BOPLA: includes internal fields)
    $user = db()->query("SELECT * FROM users WHERE id = " . (int)($payload['sub'] ?? 0))->fetch();
    echo json_encode([
        'status'  => 'ok',
        'payload' => $payload,
        'user'    => $user,  // A02: includes password hash, internal_credit_score, admin_notes
    ]);
    exit;
}

// Default: show endpoint docs
echo json_encode([
    'endpoints' => [
        '?action=login&user=alice'  => 'Get a real JWT (HS256, weak secret)',
        '?action=forge'             => 'Get a pre-forged alg:none admin token',
        '?action=me + Bearer token' => 'Verify JWT and get user data (try forged token)',
    ],
    'vulnerabilities' => [
        'alg:none'     => 'Accepted — no signature required',
        'weak_secret'  => '"secret" as HMAC key — brute-forceable with jwt_tool or hashcat',
        'no_expiry'    => 'exp claim stored but never validated',
        'bopla'        => '/me returns full DB row including password hash and internal fields',
    ],
]);
