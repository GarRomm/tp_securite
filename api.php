<?php
require_once __DIR__ . '/init.php';
header('Content-Type: application/json');

// FAILLE 1 : API sans authentification (OWASP A01:2021 - Broken Access Control)
// Toutes les actions etaient accessibles sans etre connecte : lecture des hashs MD5,
// virements entre comptes, suppression d'avis, execution de SQL brut.
// Source OWASP : https://owasp.org/Top10/A01_2021-Broken_Access_Control/
//
// Ancien code : aucune session, aucune verification d'identite.
// Ancien code vulnerable : session_start() sans options de securite.

secure_session_start();

function api_error($message, $code = 400) {
    http_response_code($code);
    echo json_encode(['error' => $message]);
    exit;
}

$me     = current_user();
$action = $_GET['action'] ?? $_POST['action'] ?? '';
$db     = db();

// ACTION : search — Recherche de produits (accessible sans connexion)
if ($action === 'search') {
    // FAILLE 2 : Injection SQL dans la recherche (OWASP A03:2021)
    // $q insere directement permettait une attaque UNION pour lire la table users
    // (avec les hashs de mots de passe) sans etre connecte.
    // Source OWASP : https://owasp.org/www-community/attacks/SQL_Injection
    //
    // Ancien code vulnerable :
    // $rows = $db->query("SELECT * FROM products WHERE name LIKE '%$q%'")->fetchAll(PDO::FETCH_ASSOC);

    $q    = $_GET['q'] ?? '';
    $stmt = $db->prepare("SELECT id, name, description, price, stock FROM products WHERE name LIKE ?");
    $stmt->execute(['%' . $q . '%']);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($rows);
    exit;
}

// ACTION : user — Voir un profil utilisateur (requiert connexion)
if ($action === 'user') {
    if (!$me) api_error('Authentification requise.', 401);

    // FAILLE 3 : Injection SQL + exposition de donnees sensibles (OWASP A03:2021)
    // $id insere directement. De plus, SELECT * retournait le hash MD5 du mot de
    // passe dans la reponse JSON.
    // Source OWASP : https://owasp.org/www-community/attacks/SQL_Injection
    //
    // Ancien code vulnerable :
    // $user = $db->query("SELECT * FROM users WHERE id=$id")->fetch(PDO::FETCH_ASSOC);

    $id   = intval($_GET['id'] ?? 0);
    $stmt = $db->prepare("SELECT id, username, role FROM users WHERE id=?");
    $stmt->execute([$id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode($user ?: null);
    exit;
}

// ACTION : users — Liste des utilisateurs (admin seulement)
if ($action === 'users') {
    // FAILLE 4 : Exposition massive de donnees sans authentification (OWASP A02:2021 + A01:2021)
    // SELECT * retournait les hashs MD5 de tous les mots de passe sans aucune verification.
    // Source OWASP : https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
    //
    // Ancien code vulnerable (pas d'auth, retournait les hashs) :
    // $rows = $db->query("SELECT * FROM users")->fetchAll(PDO::FETCH_ASSOC);

    if (!$me) api_error('Authentification requise.', 401);
    if ($me['role'] !== 'admin') api_error('Accès refusé : droits insuffisants.', 403);

    $rows = $db->query("SELECT id, username, email, role, balance FROM users")
               ->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($rows);
    exit;
}

// ACTION : orders — Commandes d'un utilisateur
if ($action === 'orders') {
    // FAILLE 5 : Injection SQL + IDOR (OWASP A03:2021 + A01:2021)
    // N'importe qui pouvait voir les commandes de n'importe quel utilisateur.
    //
    // Ancien code vulnerable :
    // $rows = $db->query("SELECT * FROM orders WHERE user_id=$uid")->fetchAll(PDO::FETCH_ASSOC);

    if (!$me) api_error('Authentification requise.', 401);

    $uid = intval($_GET['uid'] ?? 0);
    if ($me['role'] !== 'admin' && $me['id'] !== $uid) {
        api_error('Accès refusé : vous ne pouvez voir que vos propres commandes.', 403);
    }
    $stmt = $db->prepare("SELECT id, product_id, quantity, total, created_at FROM orders WHERE user_id=?");
    $stmt->execute([$uid]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($rows);
    exit;
}

// ACTION : transfer — Virement entre comptes (admin seulement)
if ($action === 'transfer' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // FAILLE 6 : Virement d'argent sans authentification (OWASP A01:2021)
    // N'importe qui pouvait virer de l'argent entre n'importe quels comptes.
    //
    // Ancien code vulnerable (pas d'auth, pas de requetes preparees) :
    // $db->query("UPDATE users SET balance=balance-$amount WHERE id=$from");
    // $db->query("UPDATE users SET balance=balance+$amount WHERE id=$to");

    if (!$me) api_error('Authentification requise.', 401);
    if ($me['role'] !== 'admin') api_error('Accès refusé.', 403);

    // Protection CSRF (OWASP A01:2021 - CSRF)
    // Un site malveillant pourrait soumettre un virement a l'insu de l'admin.
    // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
    if (!hash_equals(csrf_token(), $_POST['csrf_token'] ?? '')) {
        api_error('Jeton de sécurité invalide.', 403);
    }

    $from   = intval($_POST['from_id'] ?? 0);
    $to     = intval($_POST['to_id']   ?? 0);
    $amount = floatval($_POST['amount'] ?? 0);

    if ($amount <= 0) api_error('Montant invalide.');

    $db->prepare("UPDATE users SET balance=balance-? WHERE id=?")->execute([$amount, $from]);
    $db->prepare("UPDATE users SET balance=balance+? WHERE id=?")->execute([$amount, $to]);
    echo json_encode(['status' => 'ok', 'transferred' => $amount]);
    exit;
}

// ACTION : delete_all_reviews — Suppression d'avis (admin seulement)
if ($action === 'delete_all_reviews') {
    // FAILLE 7 : Suppression sans authentification (OWASP A01:2021)
    // N'importe qui pouvait supprimer tous les avis d'un produit.
    //
    // Ancien code vulnerable :
    // $db->query("DELETE FROM reviews WHERE product_id=$pid");

    if (!$me) api_error('Authentification requise.', 401);
    if ($me['role'] !== 'admin') api_error('Accès refusé.', 403);

    $pid = intval($_GET['pid'] ?? 0);
    $db->prepare("DELETE FROM reviews WHERE product_id=?")->execute([$pid]);
    echo json_encode(['status' => 'ok']);
    exit;
}

// FAILLE 8 CRITIQUE : Endpoint "raw_query" — execution directe de SQL brut (OWASP A03:2021)
// Cet endpoint executait litteralement n'importe quelle requete SQL passee en parametre :
//   /api.php?action=raw_query&sql=DROP TABLE users
//   /api.php?action=raw_query&sql=UPDATE users SET role='admin' WHERE id=2
// C'est l'equivalent d'un acces direct a la base de donnees pour tout le monde.
// Pour inspecter une base en developpement, utiliser des outils locaux (DBeaver, DB Browser...).
//
// Ancien endpoint SUPPRIME :
// if ($action === 'raw_query') {
//     $sql  = $_GET['sql'] ?? '';
//     $rows = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
//     echo json_encode($rows);
//     exit;
// }

// Reponse par defaut : action inconnue.
// On ne liste pas les actions disponibles pour ne pas aider un attaquant a cartographier l'API.
// Ancien code : echo json_encode(['error' => 'Action inconnue', 'actions' => [...]]);
api_error('Action inconnue.', 400);
