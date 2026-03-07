<?php
$title = 'Profil';
require_once 'header.php';
$me = require_login();

csrf_check();

// FAILLE 1 : IDOR + Injection SQL via $uid (OWASP A01:2021 + A03:2021)
// $uid venait de $_GET sans validation. Un attaquant pouvait injecter du SQL
// ou acceder au profil de n'importe quel utilisateur en devinant son ID.
// Source OWASP : https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference
//
// Ancien code vulnerable :
// $uid  = $_GET['uid'] ?? $me['id'];
// $user = $db->query("SELECT * FROM users WHERE id = $uid")->fetch(PDO::FETCH_ASSOC);

$uid  = isset($_GET['uid']) ? intval($_GET['uid']) : $me['id'];
$db   = db();
$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$uid]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) { echo '<div class="err">Utilisateur introuvable.</div>'; require_once 'footer.php'; exit; }

$ok = $error = '';
$is_own = ($me['id'] == $uid);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $is_own) {
    $action = $_POST['action'] ?? '';

    if ($action === 'update') {
        $bio   = $_POST['bio']   ?? '';
        $email = $_POST['email'] ?? '';

        // FAILLE 2 : Injection SQL en UPDATE (OWASP A03:2021)
        // En mettant ', role='admin' WHERE id=1-- dans le champ bio,
        // la requete etait detournee pour modifier le role de n'importe quel compte.
        //
        // Ancien code vulnerable :
        // $db->query("UPDATE users SET bio='$bio', email='$email' WHERE id=" . $me['id']);

        $db->prepare("UPDATE users SET bio=?, email=? WHERE id=?")->execute([$bio, $email, $me['id']]);
        $ok   = "Profil mis à jour.";
        $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$uid]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
    }

    if ($action === 'password') {
        $np = $_POST['new_password'] ?? '';

        // FAILLE 3 : Mot de passe hache avec MD5 (OWASP A02:2021)
        //
        // Ancien code vulnerable :
        // if (strlen($np) >= 4) {
        //     $db->query("UPDATE users SET password='" . md5($np) . "' WHERE id=" . $me['id']);

        if (mb_strlen($np) >= 8) {
            $db->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($np, PASSWORD_BCRYPT), $me['id']]);
            $ok = "Mot de passe modifie.";
        } else {
            $error = "Le mot de passe doit contenir au moins 8 caracteres.";
        }
    }

    if ($action === 'delete') {
        // Ancien code vulnerable :
        // $db->query("DELETE FROM users WHERE id=" . $me['id']);
        $db->prepare("DELETE FROM users WHERE id=?")->execute([$me['id']]);
        session_destroy();
        header('Location: index.php'); exit;
    }
}

// Ancien code vulnerable :
// $orders = $db->query("... WHERE o.user_id = $uid ...)->fetchAll(...);
$stmt = $db->prepare(
    "SELECT o.*, p.name as product_name FROM orders o
     JOIN products p ON o.product_id = p.id
     WHERE o.user_id = ? ORDER BY o.created_at DESC"
);
$stmt->execute([$uid]);
$orders = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="card">
  <h1>Profil de <?= htmlspecialchars($user['username']) ?></h1>
  <?php if ($ok): ?><div class="ok"><?= htmlspecialchars($ok) ?></div><?php endif; ?>
  <?php if ($error): ?><div class="err"><?= htmlspecialchars($error) ?></div><?php endif; ?>

  <p><strong>Email :</strong> <?= htmlspecialchars($user['email']) ?></p>
  <p><strong>Role :</strong> <?= htmlspecialchars($user['role']) ?></p>
  <p><strong>Solde :</strong> <?= number_format($user['balance'],2) ?> EUR</p>
  <p><strong>Bio :</strong></p>
  <div style="background:#f8f8f8;padding:10px;border-radius:5px;margin-top:6px">
    <?php
    // FAILLE 4 : XSS stocke dans la bio (OWASP A03:2021 - Stored XSS)
    // <?= $user['bio'] ?> affichait le contenu sans echappement. Un script sauvegarde
    // en bio s'executait dans le navigateur de tout visiteur du profil.
    // Source OWASP : https://owasp.org/www-community/attacks/xss/#stored-xss-attacks
    //
    // Ancien code vulnerable : <?= $user['bio'] ?: '<em>Aucune bio.</em>' ?>
    if ($user['bio']) {
        echo htmlspecialchars($user['bio'], ENT_QUOTES, 'UTF-8');
    } else {
        echo '<em style="color:#aaa">Aucune bio.</em>';
    }
    ?>
  </div>
</div>

<?php if ($is_own): ?>
<div class="card">
  <h2>Modifier mon profil</h2>
  <form method="POST">
    <?php echo csrf_field(); ?>
    <input type="hidden" name="action" value="update">
    <label style="font-size:13px">Email</label>
    <input type="email" name="email" value="<?= htmlspecialchars($user['email']) ?>">
    <label style="font-size:13px">Bio</label>
    <textarea name="bio"><?= htmlspecialchars($user['bio']) ?></textarea>
    <button class="btn" type="submit">Enregistrer</button>
  </form>
  <hr>
  <h2>Changer le mot de passe</h2>
  <form method="POST">
    <?php echo csrf_field(); ?>
    <input type="hidden" name="action" value="password">
    <input type="password" name="new_password" placeholder="Nouveau mot de passe (8 car. min.)">
    <button class="btn" type="submit">Modifier</button>
  </form>
  <hr>
  <h2 style="color:#c0392b">Zone dangereuse</h2>
  <form method="POST" onsubmit="return confirm('Supprimer votre compte ?')">
    <?php echo csrf_field(); ?>
    <input type="hidden" name="action" value="delete">
    <button class="btn btn-red" type="submit">Supprimer mon compte</button>
  </form>
</div>
<?php endif; ?>

<div class="card">
  <h2>Commandes (<?= count($orders) ?>)</h2>
  <?php if ($orders): ?>
  <table>
    <tr><th>Produit</th><th>Qte</th><th>Total</th><th>Date</th></tr>
    <?php foreach ($orders as $o): ?>
    <tr>
      <td><?= htmlspecialchars($o['product_name']) ?></td>
      <td><?= intval($o['quantity']) ?></td>
      <td><?= number_format($o['total'],2) ?> EUR</td>
      <td><?= htmlspecialchars($o['created_at']) ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
  <?php else: ?>
    <p style="color:#888">Aucune commande.</p>
  <?php endif; ?>
</div>
<?php require_once 'footer.php'; ?>
