<?php
// ============================================================
//  VulnBank – Internal JSON API
//  INTENTIONAL VULNERABILITIES:
//    A01 – No authentication required; any request returns data
//    A05 – CORS wildcard (*) allows any origin to read the response
//    A02 – Password hashes returned in user objects
//    A03 – SQLi in ?id= and ?search= parameters
// ============================================================
require_once 'db.php';

// A05: CORS misconfiguration – any origin can read this API
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, DELETE');
header('Access-Control-Allow-Headers: *');
header('Content-Type: application/json');

// A05: Version and server info exposed
header('X-VulnBank-Version: 1.0.0-dev');
header('X-Powered-By: PHP/' . PHP_VERSION);

// A01: NO AUTHENTICATION CHECK
// This entire API is public. No session, no token, nothing.
// Attacker POC:
//   curl http://localhost:8080/api.php?action=users
//   curl http://localhost:8080/api.php?action=user&id=1
//   fetch('http://localhost:8080/api.php?action=users').then(r=>r.json()).then(console.log)

$action = $_GET['action'] ?? '';

switch ($action) {

    case 'users':
        // A02: Password hashes returned in full
        // A01: All user records, no auth
        $users = db()->query("SELECT * FROM users")->fetchAll();
        echo json_encode(['status' => 'ok', 'data' => $users]);
        break;

    case 'user':
        $id = $_GET['id'] ?? '';
        // A03: SQL injection – try ?action=user&id=1 OR 1=1
        // Also: ?action=user&id=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10--
        $user = db()->query("SELECT * FROM users WHERE id = $id")->fetch();
        echo json_encode(['status' => 'ok', 'data' => $user]);
        break;

    case 'search':
        $q = $_GET['q'] ?? '';
        // A03: SQL injection in search
        $rows = db()->query("SELECT * FROM users WHERE username LIKE '%$q%' OR email LIKE '%$q%'")->fetchAll();
        echo json_encode(['status' => 'ok', 'data' => $rows]);
        break;

    case 'transactions':
        // A01: Returns ALL transactions from ALL users, no auth
        $uid  = $_GET['user_id'] ?? '';
        $where = $uid ? "WHERE from_user = $uid OR to_user = $uid" : '';
        $rows = db()->query("SELECT * FROM transactions $where ORDER BY created_at DESC")->fetchAll();
        echo json_encode(['status' => 'ok', 'data' => $rows]);
        break;

    case 'delete_user':
        // A01: Delete any user, no auth, GET request (no CSRF concern because no auth anyway)
        // curl "http://localhost:8080/api.php?action=delete_user&id=3"
        $id = (int)($_GET['id'] ?? 0);
        db()->exec("DELETE FROM users WHERE id = $id");
        echo json_encode(['status' => 'ok', 'deleted' => $id]);
        break;

    case 'config':
        // A05: Exposes internal configuration
        echo json_encode([
            'status'     => 'ok',
            'db_file'    => DB_FILE,
            'app_secret' => APP_SECRET,
            'smtp_pass'  => SMTP_PASS,
            'php_version'=> PHP_VERSION,
            'server'     => $_SERVER['SERVER_SOFTWARE'] ?? 'php-cli',
        ]);
        break;

    default:
        echo json_encode([
            'status'    => 'ok',
            'endpoints' => [
                '?action=users'                  => 'All users + password hashes (no auth)',
                '?action=user&id=1'              => 'Single user (SQLi in id)',
                '?action=search&q=admin'         => 'Search users (SQLi in q)',
                '?action=transactions'           => 'All transactions (no auth)',
                '?action=transactions&user_id=1' => 'User transactions',
                '?action=delete_user&id=3'       => 'Delete user (no auth, GET)',
                '?action=config'                 => 'App config + secrets',
            ],
        ]);
}
