<?php
$title = 'Accueil';
require_once 'header.php';

$products = db()->query("SELECT p.*, u.username as seller FROM products p JOIN users u ON p.seller_id = u.id")->fetchAll(PDO::FETCH_ASSOC);
?>
<div class="card">
  <h1>🛍️ Nos produits</h1>
  <div class="grid">
    <?php foreach ($products as $p): ?>
    <div class="product-card">
      <h2><?= htmlspecialchars($p['name']) ?></h2>
      <p style="font-size:13px;color:#666;margin-bottom:8px"><?= htmlspecialchars($p['description']) ?></p>
      <div class="price"><?= number_format($p['price'],2) ?> €</div>
      <p class="meta">Stock : <?= $p['stock'] ?> — Vendeur : <?= htmlspecialchars($p['seller']) ?></p>
      <a href="product.php?id=<?= intval($p['id']) ?>" class="btn btn-sm" style="margin-top:10px">Voir →</a>
    </div>
    <?php endforeach; ?>
  </div>
</div>
<?php require_once 'footer.php'; ?>
