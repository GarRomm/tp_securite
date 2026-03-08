<?php
$title = 'Vendre';
require_once 'header.php';
$me = require_login();

csrf_check();

$ok = $error = '';
$db = db();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'add') {
        $name  = $_POST['name']        ?? '';
        $desc  = $_POST['description'] ?? '';
        $price = floatval($_POST['price'] ?? 0);
        $stock = intval($_POST['stock']   ?? 0);

        if ($name && $price > 0) {
            if (isset($_FILES['image']) && $_FILES['image']['error'] === 0) {

                // FAILLE : Upload de fichier arbitraire (OWASP A04:2021 - Insecure Design)
                // $_FILES['image']['name'] utilise directement = RCE garanti.
                // Uploader "shell.php" puis appeler /uploads/shell.php suffisait
                // pour executer du code arbitraire sur le serveur.
                // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
                //
                // Ancien code vulnerable :
                // $filename = $_FILES['image']['name'];
                // move_uploaded_file($_FILES['image']['tmp_name'], __DIR__ . '/uploads/' . $filename);

                $max_size = 2 * 1024 * 1024;
                if ($_FILES['image']['size'] > $max_size) {
                    $error = "Image trop grande (max 2 Mo).";
                } else {
                    $ext = strtolower(pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION));
                    $allowed_ext  = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
                    $finfo = new finfo(FILEINFO_MIME_TYPE);
                    $mime_type = $finfo->file($_FILES['image']['tmp_name']);
                    $allowed_mime = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

                    if (!in_array($ext, $allowed_ext, true) || !in_array($mime_type, $allowed_mime, true)) {
                        $error = "Type de fichier non autorisé. Seules les images JPG, PNG, GIF, WEBP sont acceptées.";
                    } else {
                        // Nom aleatoire : l'utilisateur n'a aucun controle sur le nom final
                        $safe_filename = bin2hex(random_bytes(16)) . '.' . $ext;
                        $upload_dir    = __DIR__ . '/uploads/';
                        // Cree le dossier uploads/ s'il n'existe pas encore (permissions 755)
                        if (!is_dir($upload_dir)) {
                            mkdir($upload_dir, 0755, true);
                        }
                        if (!move_uploaded_file($_FILES['image']['tmp_name'], $upload_dir . $safe_filename)) {
                            $error = "Erreur lors de l'upload.";
                        }
                    }
                }
            }

            if (!$error) {
                $db->prepare("INSERT INTO products (name,description,price,stock,seller_id) VALUES (?,?,?,?,?)")
                   ->execute([$name, $desc, $price, $stock, $me['id']]);
                $ok = "Produit ajoute.";
            }
        } else {
            $error = "Nom et prix obligatoires.";
        }
    }

    if ($action === 'delete') {
        // FAILLE : Injection SQL + IDOR (OWASP A03:2021 + A01:2021)
        // $pid etait insere directement dans la requete. De plus, aucune verification
        // que le produit appartient au vendeur connecte : n'importe quel vendeur
        // pouvait supprimer les produits des autres en forgeant un POST.
        // Source OWASP : https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference
        //
        // Ancien code vulnerable :
        // $pid = $_POST['pid'] ?? 0;
        // $db->query("DELETE FROM products WHERE id=$pid");

        $pid = intval($_POST['pid'] ?? 0);
        // AND seller_id=? garantit que seul le proprietaire peut supprimer son produit
        $db->prepare("DELETE FROM products WHERE id=? AND seller_id=?")
           ->execute([$pid, $me['id']]);
        $ok = "Produit supprime.";
    }

    if ($action === 'update_price') {
        // FAILLE : Injection SQL + IDOR (OWASP A03:2021 + A01:2021)
        // Meme double faille que pour la suppression : $newprice et $pid injectes
        // directement, et aucun controle de propriete.
        //
        // Ancien code vulnerable :
        // $pid      = $_POST['pid'] ?? 0;
        // $newprice = $_POST['new_price'] ?? 0;
        // $db->query("UPDATE products SET price=$newprice WHERE id=$pid");

        $pid      = intval($_POST['pid'] ?? 0);
        $newprice = floatval($_POST['new_price'] ?? 0);

        if ($newprice <= 0) {
            $error = "Le prix doit être positif.";
        } else {
            $db->prepare("UPDATE products SET price=? WHERE id=? AND seller_id=?")
               ->execute([$newprice, $pid, $me['id']]);
            $ok = "Prix mis a jour.";
        }
    }
}

$stmt = $db->prepare("SELECT * FROM products WHERE seller_id = ?");
$stmt->execute([$me['id']]);
$my_products = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="card">
  <h1>Espace vendeur</h1>
  <?php if ($ok): ?><div class="ok"><?= htmlspecialchars($ok) ?></div><?php endif; ?>
  <?php if ($error): ?><div class="err"><?= htmlspecialchars($error) ?></div><?php endif; ?>

  <h2>Ajouter un produit</h2>
  <form method="POST" enctype="multipart/form-data">
    <?php echo csrf_field(); ?>
    <input type="hidden" name="action" value="add">
    <label style="font-size:13px">Nom du produit</label>
    <input type="text" name="name" placeholder="Ex: Clé USB 128Go">
    <label style="font-size:13px">Description</label>
    <textarea name="description" placeholder="Décrivez votre produit..."></textarea>
    <label style="font-size:13px">Prix (EUR)</label>
    <input type="number" name="price" step="0.01" min="0.01">
    <label style="font-size:13px">Stock initial</label>
    <input type="number" name="stock" min="0" value="10">
    <label style="font-size:13px">Image (JPG, PNG, GIF, WEBP - max 2 Mo)</label>
    <input type="file" name="image" accept="image/jpeg,image/png,image/gif,image/webp" style="background:none;border:none;padding:0">
    <button class="btn btn-green" type="submit" style="margin-top:6px">Ajouter</button>
  </form>
</div>

<div class="card">
  <h2>Mes produits (<?= count($my_products) ?>)</h2>
  <?php if ($my_products): ?>
  <table>
    <tr><th>Nom</th><th>Prix</th><th>Stock</th><th>Actions</th></tr>
    <?php foreach ($my_products as $p): ?>
    <tr>
      <td><a href="product.php?id=<?= intval($p['id']) ?>"><?= htmlspecialchars($p['name']) ?></a></td>
      <td><?= number_format($p['price'],2) ?> EUR</td>
      <td><?= intval($p['stock']) ?></td>
      <td style="display:flex;gap:6px">
        <form method="POST" style="margin:0;display:flex;gap:4px">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="pid" value="<?= intval($p['id']) ?>">
          <input type="number" name="new_price" value="<?= $p['price'] ?>" step="0.01" min="0.01" style="width:80px;padding:3px;font-size:12px;margin:0">
          <button class="btn btn-sm btn-blue" name="action" value="update_price" type="submit">Modifier</button>
        </form>
        <form method="POST" style="margin:0">
          <?php echo csrf_field(); ?>
          <input type="hidden" name="pid" value="<?= intval($p['id']) ?>">
          <button class="btn btn-sm btn-red" name="action" value="delete" type="submit">Suppr.</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </table>
  <?php else: ?>
    <p style="color:#888">Vous n'avez pas encore de produits.</p>
  <?php endif; ?>
</div>
<?php require_once 'footer.php'; ?>
