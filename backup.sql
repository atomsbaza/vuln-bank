-- VulnBank Database Backup
-- A05: SQL dump left in webroot, accessible at /backup.sql
-- Generated: 2024-06-01 03:00:01
-- A02: Contains plaintext MD5 password hashes

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    balance REAL DEFAULT 5000.00,
    account_number TEXT,
    bio TEXT DEFAULT '',
    avatar_url TEXT DEFAULT '',
    security_q TEXT,
    security_a TEXT
);

INSERT INTO users VALUES(1,'admin','0192023a7bbd73250516f069df18b500','admin@vulnbank.local','admin',999999.0,'VB-0000001','','','Favourite colour?','blue');
INSERT INTO users VALUES(2,'alice','482c811da5d5b4bc6d497ffa98491e38','alice@example.com','user',15000.0,'VB-0001001','','','Pet name?','fluffy');
INSERT INTO users VALUES(3,'bob','0d107d09f5bbe40cade3de5c71e9e9b7','bob@example.com','user',3200.0,'VB-0001002','','','Birth city?','bangkok');
INSERT INTO users VALUES(4,'charlie','f59571e2deb7d6b2bd76e0bdde2a97f7','charlie@example.com','user',87500.0,'VB-0001003','','','Pet name?','max');

CREATE TABLE transactions (
    id INTEGER PRIMARY KEY,
    from_user INTEGER,
    to_user INTEGER,
    amount REAL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO transactions VALUES(1,2,3,500.0,'Rent – October','2024-06-01 00:00:01');
INSERT INTO transactions VALUES(2,3,2,150.0,'Dinner split','2024-06-01 00:00:02');
INSERT INTO transactions VALUES(3,4,2,2000.0,'Freelance invoice #104','2024-06-01 00:00:03');
INSERT INTO transactions VALUES(4,1,2,5000.0,'Welcome bonus','2024-06-01 00:00:04');

-- Admin notes (should not be in backup):
-- Deploy password: deploy@vulnbank2024!
-- SSH key passphrase: VulnBank#SSH2024
-- Staging DB: postgresql://admin:St@g1ng_P@ss@staging-db.vulnbank.local:5432/vulnbank
