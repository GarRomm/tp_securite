<?php
define('DB', __DIR__ . '/shop.db');

// Note : shop.db est accessible via HTTP. En production, le placer hors du dossier public.

function db() {
    $pdo = new PDO('sqlite:' . DB);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}

function init() {
    $pdo = db();
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            bio TEXT DEFAULT '',
            balance REAL DEFAULT 100.0
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            description TEXT,
            price REAL,
            stock INTEGER DEFAULT 10,
            seller_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total REAL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            user_id INTEGER,
            content TEXT,
            rating INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_id INTEGER,
            to_id INTEGER,
            content TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            discount REAL,
            used INTEGER DEFAULT 0
        );
    ");

    // FAILLE : Mots de passe haches avec MD5 (OWASP A02:2021 - Cryptographic Failures)
    // MD5 est concu pour etre rapide : un attaquant qui vole la BDD retrouve les mots
    // de passe en quelques secondes via des Rainbow Tables ou du materiel specialise.
    // Exemple : md5("admin") = "21232f..." retrouve instantanement sur crackstation.net
    // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    //
    // Ancien code vulnerable :
    // ['alice', md5('alice123'), 'alice@vulnshop.fr', 'user', 'Acheteuse passionnee.', 500.0],
    // ['bob',   md5('bob123'),   'bob@vulnshop.fr',   'user', 'Vendeur de gadgets.',   200.0],
    // ['admin', md5('admin'),    'admin@vulnshop.fr', 'admin','Administrateur.',        9999.0],

    $users = [
        ['alice', password_hash('alice123', PASSWORD_BCRYPT), 'alice@vulnshop.fr', 'user',  'Acheteuse passionnee.', 500.0],
        ['bob',   password_hash('bob123',   PASSWORD_BCRYPT), 'bob@vulnshop.fr',   'user',  'Vendeur de gadgets.',   200.0],
        ['admin', password_hash('admin',    PASSWORD_BCRYPT), 'admin@vulnshop.fr', 'admin', 'Administrateur.',       9999.0],
    ];
    // PASSWORD_BCRYPT : algorithme lent avec sel aleatoire integre. Deux utilisateurs
    // avec le meme mot de passe produiront des hashes differents.

    $s = $pdo->prepare("INSERT OR IGNORE INTO users (username,password,email,role,bio,balance) VALUES (?,?,?,?,?,?)");
    foreach ($users as $u) $s->execute($u);

    $products = [
        [1, 'Cle USB 64Go',    'Cle USB rapide et fiable.',        12.99, 50, 2],
        [2, 'Souris sans fil', 'Ergonomique et precise.',           24.99, 30, 2],
        [3, 'Casque audio',    'Son haute fidelite.',               49.99, 15, 1],
        [4, 'Webcam HD',       'Ideale pour les visioconferences.', 39.99, 20, 1],
    ];
    $s = $pdo->prepare("INSERT OR IGNORE INTO products (id,name,description,price,stock,seller_id) VALUES (?,?,?,?,?,?)");
    foreach ($products as $p) $s->execute($p);

    $pdo->exec("INSERT OR IGNORE INTO coupons (code,discount) VALUES ('PROMO10', 10), ('VIP50', 50)");
}

if (!file_exists(DB)) init();

function current_user() {
    if (empty($_SESSION['uid'])) return null;
    $s = db()->prepare("SELECT * FROM users WHERE id = ?");
    $s->execute([$_SESSION['uid']]);
    return $s->fetch(PDO::FETCH_ASSOC) ?: null;
}

function require_login() {
    $u = current_user();
    if (!$u) { header('Location: login.php'); exit; }
    return $u;
}

// Protection CSRF (OWASP A01:2021 - CSRF)
// Un site malveillant peut soumettre un formulaire a la place de l'utilisateur connecte.
// La solution : un jeton secret unique par session dans chaque formulaire.
// Le serveur rejette toute requete qui ne fournit pas ce jeton.
// Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field() {
    return '<input type="hidden" name="csrf_token" value="' . csrf_token() . '">';
}

function csrf_check() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // hash_equals() evite les attaques temporelles (timing attacks)
        if (!hash_equals(csrf_token(), $_POST['csrf_token'] ?? '')) {
            http_response_code(403);
            die('Requête refusée : jeton de sécurité invalide ou manquant.');
        }
    }
}

// FAILLE : session_start() sans options de securite dans api.php et logout.php
// (OWASP A07:2021 - Authentication Failures)
// Centraliser ici les options de session garantit qu'elles sont toujours appliquees,
// peu importe le fichier d'entree. Voir aussi header.php.
// Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
function secure_session_start() {
    ini_set('session.cookie_httponly', 1);    // Cookie illisible par JavaScript
    ini_set('session.cookie_samesite', 'Strict'); // Cookie non envoye depuis un site tiers
    ini_set('session.use_strict_mode', 1);   // Rejette les IDs de session non generes par le serveur
    ini_set('session.use_only_cookies', 1);  // Interdit l'ID de session dans l'URL
    session_start();
}
