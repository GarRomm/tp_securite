<?php
$title = 'Administration';
require_once 'header.php';
$me = require_login();

// FAILLE 1 : Controle d'acces casse (OWASP A01:2021 - Broken Access Control)
// L'ancien code affichait un message d'erreur mais continuait l'execution.
// N'importe qui pouvait envoyer des requetes POST pour executer les actions admin.
// Source OWASP : https://owasp.org/Top10/A01_2021-Broken_Access_Control/
//
// Ancien code vulnerable :
// if ($me['role'] !== 'admin') {
//     echo '<div class="err">Acces reserve aux administrateurs.</div>';
// }
// ^ Le script continuait apres !

if ($me['role'] !== 'admin') {
    echo '<div class="err">Accès réservé aux administrateurs.</div>';
    require_once 'footer.php';
    exit;
}

csrf_check();

$db  = db();
$ok  = $error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // FAILLE 2 : Injection SQL dans toutes les actions admin (OWASP A03:2021)
    // Chaque action inserait les variables directement dans les requetes.
    // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

    if ($action === 'delete_user') {
        // Ancien : $db->query("DELETE FROM users WHERE id=$uid");
        $uid = intval($_POST['uid'] ?? 0);
        $db->prepare("DELETE FROM users WHERE id=?")->execute([$uid]);
        $ok = "Utilisateur supprime.";
    }

    if ($action === 'set_role') {
        // Ancien : $db->query("UPDATE users SET role='$role' WHERE id=$uid");
        $uid           = intval($_POST['uid'] ?? 0);
        $allowed_roles = ['user', 'admin'];
        $role          = $_POST['role'] ?? 'user';
        if (!in_array($role, $allowed_roles, true)) {
            $role = 'user';
        }
        $db->prepare("UPDATE users SET role=? WHERE id=?")->execute([$role, $uid]);
        $ok = "Role mis a jour.";
    }

    if ($action === 'delete_product') {
        // Ancien : $db->query("DELETE FROM products WHERE id=$pid");
        $pid = intval($_POST['pid'] ?? 0);
        $db->prepare("DELETE FROM products WHERE id=?")->execute([$pid]);
        $ok = "Produit supprime.";
    }

    if ($action === 'delete_review') {
        // Ancien : $db->query("DELETE FROM reviews WHERE id=$rid");
        $rid = intval($_POST['rid'] ?? 0);
        $db->prepare("DELETE FROM reviews WHERE id=?")->execute([$rid]);
        $ok = "Avis supprime.";
    }

    if ($action === 'add_balance') {
        // Ancien : $db->query("UPDATE users SET balance=balance+$amount WHERE id=$uid");
        $uid    = intval($_POST['uid'] ?? 0);
        $amount = floatval($_POST['amount'] ?? 0);
        $db->prepare("UPDATE users SET balance=balance+? WHERE id=?")->execute([$amount, $uid]);
        $ok = "Solde modifie.";
    }
}

$users    = $db->query("SELECT * FROM users")->fetchAll(PDO::FETCH_ASSOC);
$products = $db->query("SELECT * FROM products")->fetchAll(PDO::FETCH_ASSOC);
$orders   = $db->query("SELECT o.*, u.username, p.name as product_name FROM orders o JOIN users u ON o.user_id=u.id JOIN products p ON o.product_id=p.id ORDER BY o.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
$reviews  = $db->query("SELECT r.*, u.username, p.name as product_name FROM reviews r JOIN users u ON r.user_id=u.id JOIN products p ON r.product_id=p.id ORDER BY r.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
?>

<?php if ($ok): ?><div class="ok"><?= htmlspecialchars($ok) ?></div><?php endif; ?>

<div class="card">
  <h1>Administration</h1>

  <h2>Utilisateurs</h2>
  <table>
    <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Solde</th><th>Actions</th></tr>
    <?php foreach ($users as $u): ?>
    <tr>
      <td><?= intval($u['id']) ?></td>
      <td><a href="profile.php?uid=<?= intval($u['id']) ?>"><?= htmlspecialchars($u['username']) ?></a></td>
      <td><?= htmlspecialchars($u['email']) ?></td>
      <td><?= htmlspecialchars($u['role']) ?></td>
      <td><?= number_format($u['balance'],2) ?> EUR</td>
      <?php
      // FAILLE 3 : Hashs MD5 des mots de passe affiches dans le HTML (OWASP A02:2021)
      // Afficher les hashs dans l'interface facilite leur craquage. Colonne supprimee.
      // Ancien code vulnerable : <td>echo $u['password'];</td>
      ?>
      <td style="display:flex;gap:6px;flex-wrap:wrap">
        <form method="POST" style="margin:0;display:flex;gap:4px">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="uid" value="<?= intval($u['id']) ?>">
          <select name="role" style="padding:3px;font-size:12px;width:auto;margin:0">
            <option <?= $u['role']==='user' ?'selected':'' ?>>user</option>
            <option <?= $u['role']==='admin'?'selected':'' ?>>admin</option>
          </select>
          <button class="btn btn-sm btn-blue" name="action" value="set_role" type="submit">Role</button>
        </form>
        <form method="POST" style="margin:0;display:flex;gap:4px">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="uid" value="<?= intval($u['id']) ?>">
          <input type="number" name="amount" placeholder="EUR" style="width:60px;padding:3px;font-size:12px;margin:0">
          <button class="btn btn-sm btn-green" name="action" value="add_balance" type="submit">+Solde</button>
        </form>
        <form method="POST" style="margin:0" onsubmit="return confirm('Supprimer ?')">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="uid" value="<?= intval($u['id']) ?>">
          <button class="btn btn-sm btn-red" name="action" value="delete_user" type="submit">Suppr.</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </table>
</div>

<div class="card">
  <h2>Produits</h2>
  <table>
    <tr><th>ID</th><th>Nom</th><th>Prix</th><th>Stock</th><th>Action</th></tr>
    <?php foreach ($products as $p): ?>
    <tr>
      <td><?= intval($p['id']) ?></td>
      <td><?= htmlspecialchars($p['name']) ?></td>
      <td><?= number_format($p['price'],2) ?> EUR</td>
      <td><?= intval($p['stock']) ?></td>
      <td>
        <form method="POST" style="margin:0" onsubmit="return confirm('Supprimer ?')">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="pid" value="<?= intval($p['id']) ?>">
          <button class="btn btn-sm btn-red" name="action" value="delete_product" type="submit">Suppr.</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </table>
</div>

<div class="card">
  <h2>Avis recents</h2>
  <table>
    <tr><th>Produit</th><th>Auteur</th><th>Contenu</th><th>Note</th><th>Action</th></tr>
    <?php foreach ($reviews as $rv): ?>
    <tr>
      <td><?= htmlspecialchars($rv['product_name']) ?></td>
      <td><?= htmlspecialchars($rv['username']) ?></td>
      <td>
        <?php
        // FAILLE 4 : XSS stocke dans les avis (OWASP A03:2021 - Stored XSS)
        // echo $rv['content']; sans echappement : un avis malveillant pouvait voler
        // la session de l'admin qui consulte ce tableau de bord.
        // Ancien code vulnerable : echo $rv['content'];
        echo htmlspecialchars($rv['content'], ENT_QUOTES, 'UTF-8');
        ?>
      </td>
      <td><?= intval($rv['rating']) ?>/5</td>
      <td>
        <form method="POST" style="margin:0">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="rid" value="<?= intval($rv['id']) ?>">
          <button class="btn btn-sm btn-red" name="action" value="delete_review" type="submit">Suppr.</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </table>
</div>

<div class="card">
  <h2>Commandes</h2>
  <table>
    <tr><th>ID</th><th>Client</th><th>Produit</th><th>Qte</th><th>Total</th><th>Date</th></tr>
    <?php foreach ($orders as $o): ?>
    <tr>
      <td><?= intval($o['id']) ?></td>
      <td><?= htmlspecialchars($o['username']) ?></td>
      <td><?= htmlspecialchars($o['product_name']) ?></td>
      <td><?= intval($o['quantity']) ?></td>
      <td><?= number_format($o['total'],2) ?> EUR</td>
      <td><?= htmlspecialchars($o['created_at']) ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
</div>
<?php require_once 'footer.php'; ?>
