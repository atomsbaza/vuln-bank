<?php
// ============================================================
//  VulnBank – Database layer
//  INTENTIONAL VULNERABILITIES:
//    A02 – MD5 password hashing, hardcoded secrets
//    A05 – Verbose PDO errors, DB path exposed in comments
// ============================================================

// A02: Hardcoded application secrets in source code
define('DB_FILE',    __DIR__ . '/vulnbank.db');
define('APP_SECRET', 'vulnbank$ecret_2020');   // weak, guessable, year-based
define('SMTP_PASS',  'Sm7pP@ss2020!');         // another hardcoded credential

function db(): PDO {
    static $pdo;
    if (!$pdo) {
        $pdo = new PDO('sqlite:' . DB_FILE);
        // A05: ERRMODE_EXCEPTION exposes stack traces + file paths in production
        $pdo->setAttribute(PDO::ATTR_ERRMODE,         PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    }
    return $pdo;
}

// ── Schema ───────────────────────────────────────────────────
db()->exec("
    CREATE TABLE IF NOT EXISTS users (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        username             TEXT NOT NULL UNIQUE,
        password             TEXT NOT NULL,
        email                TEXT,
        role                 TEXT DEFAULT 'user',
        balance              REAL DEFAULT 5000.00,
        account_number       TEXT,
        bio                  TEXT DEFAULT '',
        avatar_url           TEXT DEFAULT '',
        security_q           TEXT DEFAULT 'What is your pet name?',
        security_a           TEXT DEFAULT '',
        internal_credit_score INTEGER DEFAULT 720,
        admin_notes          TEXT DEFAULT '',
        totp_secret          TEXT DEFAULT '',
        totp_enabled         INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user   INTEGER,
        to_user     INTEGER,
        amount      REAL,
        description TEXT,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        username   TEXT,
        content    TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS vouchers (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        code     TEXT UNIQUE,
        discount REAL DEFAULT 100.00,
        used     INTEGER DEFAULT 0,
        used_by  INTEGER DEFAULT NULL
    );
    CREATE TABLE IF NOT EXISTS reset_tokens (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        token      TEXT,
        expires_at DATETIME,
        used       INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS loans (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        amount     REAL,
        months     INTEGER,
        monthly    REAL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
");

// ── Seed ─────────────────────────────────────────────────────
if (!db()->query("SELECT 1 FROM users LIMIT 1")->fetch()) {
    // A05: default credentials shipped with the app
    // A02: MD5 with no salt
    $ins = db()->prepare(
        "INSERT INTO users (id,username,password,email,role,balance,account_number,security_q,security_a)
         VALUES (?,?,?,?,?,?,?,?,?)"
    );
    foreach ([
        [1,'admin',   md5('admin123'),    'admin@vulnbank.local',  'admin', 999999, 'VB-0000001','Favourite colour?','blue'],
        [2,'alice',   md5('password123'), 'alice@example.com',     'user',  15000,  'VB-0001001','Pet name?',        'fluffy'],
        [3,'bob',     md5('letmein'),     'bob@example.com',       'user',  3200,   'VB-0001002','Birth city?',      'bangkok'],
        [4,'charlie', md5('charlie1'),    'charlie@example.com',   'user',  87500,  'VB-0001003','Pet name?',        'max'],
    ] as $r) $ins->execute($r);

    db()->exec("INSERT INTO transactions(from_user,to_user,amount,description) VALUES
        (2,3,500,'Rent – October'),
        (3,2,150,'Dinner split'),
        (4,2,2000,'Freelance invoice #104'),
        (1,2,5000,'Welcome bonus'),
        (2,4,300,'Concert tickets')
    ");

    db()->exec("INSERT INTO messages(user_id,username,content) VALUES
        (2,'alice','Hello VulnBank community! Love the new dashboard.'),
        (3,'bob','Transfer speeds are great. Happy customer here.')
    ");

    db()->exec("INSERT INTO vouchers(code,discount) VALUES
        ('WELCOME50',50.00),
        ('SAVE100',100.00),
        ('VIP200',200.00),
        ('FREEFEE',999.00)
    ");
}
