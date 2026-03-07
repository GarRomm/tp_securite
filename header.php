<?php
// FAILLE : Session sans options de securite (OWASP A07:2021 - Authentication Failures)
// Le cookie de session pouvait etre vole via JS (XSS), envoye vers des sites tiers
// (CSRF) ou lu dans l'URL. On configure les options AVANT session_start().
// Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
//
// Ancien code vulnerable :
// session_start();

ini_set('session.cookie_httponly', 1);    // Cookie illisible par JavaScript
ini_set('session.cookie_samesite', 'Strict'); // Cookie non envoye depuis un site tiers
ini_set('session.use_strict_mode', 1);   // Rejette les IDs de session non generes par le serveur
ini_set('session.use_only_cookies', 1);  // Interdit l'ID de session dans l'URL

session_start();

require_once __DIR__ . '/init.php';
$me = current_user();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>VulnShop — <?= $title ?? 'Boutique' ?></title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#f0f2f5;color:#222}
nav{background:#1a1a2e;padding:0 30px;height:54px;display:flex;align-items:center;gap:20px}
nav .brand{font-size:20px;font-weight:bold;color:#e94560;margin-right:auto}
nav a{color:#aaa;text-decoration:none;font-size:14px} nav a:hover{color:#fff}
nav .user{color:#888;font-size:13px}
.wrap{max-width:1000px;margin:26px auto;padding:0 16px}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:22px;margin-bottom:18px}
h1{font-size:22px;margin-bottom:16px;color:#1a1a2e}
h2{font-size:17px;margin-bottom:12px;color:#1a1a2e}
input,textarea,select{width:100%;padding:8px 10px;border:1px solid #ddd;border-radius:5px;font-size:14px;margin-bottom:10px;font-family:Arial,sans-serif}
textarea{height:80px;resize:vertical}
.btn{display:inline-block;padding:8px 16px;background:#1a1a2e;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:14px;text-decoration:none}
.btn-red{background:#c0392b}.btn-green{background:#27ae60}.btn-blue{background:#2980b9}
.btn-sm{padding:4px 10px;font-size:12px}
.ok{background:#d4edda;border:1px solid #c3e6cb;color:#155724;padding:9px 12px;border-radius:5px;margin-bottom:12px;font-size:13px}
.err{background:#f8d7da;border:1px solid #f5c6cb;color:#721c24;padding:9px 12px;border-radius:5px;margin-bottom:12px;font-size:13px}
.meta{font-size:12px;color:#999}
hr{border:none;border-top:1px solid #eee;margin:14px 0}
table{width:100%;border-collapse:collapse;font-size:14px}
th{background:#f0f2f5;padding:8px;text-align:left;border:1px solid #ddd}
td{padding:8px;border:1px solid #ddd}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
.product-card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:16px}
.price{font-size:20px;font-weight:bold;color:#e94560;margin:8px 0}
.stars{color:#f39c12}
</style>
</head>
<body>
<nav>
  <span class="brand">VulnShop</span>
  <a href="index.php">Accueil</a>
  <a href="search.php">Recherche</a>
  <?php if ($me): ?>
    <a href="profile.php">Mon profil</a>
    <a href="messages.php">Messages</a>
    <?php if ($me['role']==='admin'): ?><a href="admin.php">Admin</a><?php endif; ?>
    <span class="user">👤 <?= htmlspecialchars($me['username']) ?> — <?= number_format($me['balance'],2) ?>EUR</span>
    <a href="logout.php">Déconnexion</a>
  <?php else: ?>
    <a href="login.php">Connexion</a>
    <a href="register.php">Inscription</a>
  <?php endif; ?>
</nav>
<div class="wrap">
