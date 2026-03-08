<?php
$title = 'Produit';
require_once 'header.php';

csrf_check();

// FAILLE 1 : Injection SQL via l'ID du produit (OWASP A03:2021 - Injection)
// Un attaquant pouvait injecter une clause UNION pour lire d'autres tables.
// Source OWASP : https://owasp.org/www-community/attacks/SQL_Injection
//
// Ancien code vulnerable :
// $id = $_GET['id'] ?? 0;
// $product = db()->query("SELECT p.*, ... WHERE p.id = $id")->fetch(...);

$id = intval($_GET['id'] ?? 0);

$stmt = db()->prepare(
    "SELECT p.*, u.username as seller, u.email as seller_email
     FROM products p JOIN users u ON p.seller_id = u.id
     WHERE p.id = ?"
);
$stmt->execute([$id]);
$product = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$product) {
    echo '<div class="err">Produit introuvable.</div>';
    require_once 'footer.php'; exit;
}

$ok = $error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $me) {
    $action = $_POST['action'] ?? '';

    if ($action === 'buy') {
        $qty    = intval($_POST['qty'] ?? 1);
        $coupon = trim($_POST['coupon'] ?? '');
        $total  = $product['price'] * $qty;

        if ($coupon !== '') {
            // FAILLE 2 : Injection SQL via le code promo (OWASP A03:2021)
            // Un attaquant pouvait saisir ' OR '1'='1 pour toujours obtenir une reduction.
            //
            // Ancien code vulnerable :
            // $c = db()->query("SELECT * FROM coupons WHERE code='$coupon' AND used=0")->fetch(...);
            // db()->query("UPDATE coupons SET used=used+1 WHERE code='$coupon'");

            $stmt_c = db()->prepare("SELECT * FROM coupons WHERE code=? AND used=0");
            $stmt_c->execute([$coupon]);
            $c = $stmt_c->fetch(PDO::FETCH_ASSOC);
            if ($c) {
                $total = $total * (1 - $c['discount'] / 100);
                db()->prepare("UPDATE coupons SET used=used+1 WHERE code=?")
                    ->execute([$coupon]);
            }
        }

        if ($qty < 1 || $qty > $product['stock']) {
            $error = "Quantité invalide.";
        } elseif ($me['balance'] < $total) {
            $error = "Solde insuffisant.";
        } else {
            db()->prepare("INSERT INTO orders (user_id,product_id,quantity,total) VALUES (?,?,?,?)")
               ->execute([$me['id'], $id, $qty, $total]);

            // FAILLE 3 : Injection SQL dans les UPDATE de solde et stock (OWASP A03:2021)
            // Defense en profondeur : toujours utiliser des requetes preparees.
            //
            // Ancien code vulnerable :
            // db()->query("UPDATE users SET balance=balance-$total WHERE id=" . $me['id']);
            // db()->query("UPDATE products SET stock=stock-$qty WHERE id=$id");

            db()->prepare("UPDATE users SET balance=balance-? WHERE id=?")
               ->execute([$total, $me['id']]);
            db()->prepare("UPDATE products SET stock=stock-? WHERE id=?")
               ->execute([$qty, $id]);

            $ok = "Commande passée ! Total : " . number_format($total,2) . " EUR";
            $me = current_user();
        }
    }

    if ($action === 'review') {
        $content = $_POST['content'] ?? '';
        $rating  = intval($_POST['rating'] ?? 5);
        $rating  = max(1, min(5, $rating));
        if ($content) {
            db()->prepare("INSERT INTO reviews (product_id,user_id,content,rating) VALUES (?,?,?,?)")
               ->execute([$id, $me['id'], $content, $rating]);
            header("Location: product.php?id=$id"); exit;
        }
    }
}

// Ancien code vulnerable :
// $reviews = db()->query("... WHERE r.product_id = $id ...)->fetchAll(...);

$stmt_r = db()->prepare(
    "SELECT r.*, u.username FROM reviews r
     JOIN users u ON r.user_id = u.id
     WHERE r.product_id = ? ORDER BY r.created_at DESC"
);
$stmt_r->execute([$id]);
$reviews = $stmt_r->fetchAll(PDO::FETCH_ASSOC);

$avg = count($reviews) ? round(array_sum(array_column($reviews,'rating')) / count($reviews),1) : null;
?>

<div class="card">
  <h1><?= htmlspecialchars($product['name']) ?></h1>
  <p style="color:#666;margin-bottom:12px"><?= htmlspecialchars($product['description']) ?></p>
  <div class="price"><?= number_format($product['price'],2) ?> EUR</div>
  <p class="meta" style="margin:8px 0">
    Stock : <?= intval($product['stock']) ?> —
    Vendeur : <?= htmlspecialchars($product['seller']) ?> (<?= htmlspecialchars($product['seller_email']) ?>) —
    <?php if ($avg): ?><span class="stars"><?= str_repeat('★',(int)$avg) ?></span> <?= $avg ?>/5<?php endif; ?>
  </p>

  <?php if ($ok): ?><div class="ok"><?= htmlspecialchars($ok) ?></div><?php endif; ?>
  <?php if ($error): ?><div class="err"><?= htmlspecialchars($error) ?></div><?php endif; ?>

  <?php if ($me): ?>
  <form method="POST" style="margin-top:14px">
    <?php echo csrf_field(); ?>
    <div style="display:flex;gap:10px;align-items:center">
      <input type="number" name="qty" value="1" min="1" max="<?= intval($product['stock']) ?>" style="width:80px;margin:0">
      <input type="text" name="coupon" placeholder="Code promo" style="width:160px;margin:0">
      <button class="btn btn-green" name="action" value="buy" type="submit">Acheter</button>
    </div>
  </form>
  <?php endif; ?>
</div>

<div class="card">
  <h2>Avis clients (<?= count($reviews) ?>)</h2>

  <?php foreach ($reviews as $rv): ?>
  <div style="border-bottom:1px solid #eee;padding:10px 0">
    <p class="meta">
      <strong><?= htmlspecialchars($rv['username']) ?></strong> —
      <span class="stars"><?= str_repeat('★', intval($rv['rating'])) ?></span> —
      <?= htmlspecialchars($rv['created_at']) ?>
    </p>
    <div style="margin-top:6px">
      <?php
      // FAILLE 4 : XSS stocke dans les avis (OWASP A03:2021 - Stored XSS)
      // Un avis contenant du JavaScript s'executait dans le navigateur de chaque visiteur.
      // Source OWASP : https://owasp.org/www-community/attacks/xss/#stored-xss-attacks
      //
      // Ancien code vulnerable : echo $rv['content'];
      echo htmlspecialchars($rv['content'], ENT_QUOTES, 'UTF-8');
      ?>
    </div>
  </div>
  <?php endforeach; ?>

  <?php if ($me): ?>
  <form method="POST" style="margin-top:16px">
    <?php echo csrf_field(); ?>
    <label style="font-size:13px">Note</label>
    <select name="rating" style="width:auto;margin-bottom:10px">
      <?php for($i=5;$i>=1;$i--): ?>
        <option value="<?= $i ?>"><?= str_repeat('★',$i) ?></option>
      <?php endfor; ?>
    </select>
    <textarea name="content" placeholder="Votre avis..."></textarea>
    <button class="btn" name="action" value="review" type="submit">Publier</button>
  </form>
  <?php else: ?>
    <p style="color:#888;font-size:13px;margin-top:10px"><a href="login.php">Connectez-vous</a> pour laisser un avis.</p>
  <?php endif; ?>
</div>
<?php require_once 'footer.php'; ?>
