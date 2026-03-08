<?php
$title = 'Recherche';
require_once 'header.php';

$q       = $_GET['q'] ?? '';
$sort    = $_GET['sort'] ?? 'name';
$results = [];

if ($q !== '') {

    // FAILLE 1 : Injection SQL dans la clause WHERE (OWASP A03:2021 - Injection)
    // $q insere directement permet une attaque UNION : l'attaquant peut recuperer
    // les donnees de n'importe quelle table (users, mots de passe...).
    // Source OWASP : https://owasp.org/www-community/attacks/SQL_Injection
    //
    // FAILLE 2 : Injection SQL dans ORDER BY (OWASP A03:2021)
    // Les requetes preparees ne protegent pas les noms de colonnes. $sort doit
    // etre valide par une liste blanche avant d'etre insere dans la requete.
    // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
    //
    // Ancien code vulnerable :
    // $results = db()->query(
    //     "SELECT p.*, u.username as seller FROM products p
    //      JOIN users u ON p.seller_id = u.id
    //      WHERE p.name LIKE '%$q%' OR p.description LIKE '%$q%'
    //      ORDER BY $sort ASC"
    // )->fetchAll(PDO::FETCH_ASSOC);

    $allowed_sorts = ['name', 'price'];
    if (!in_array($sort, $allowed_sorts, true)) {
        $sort = 'name';
    }

    $stmt = db()->prepare(
        "SELECT p.*, u.username as seller FROM products p
         JOIN users u ON p.seller_id = u.id
         WHERE p.name LIKE ? OR p.description LIKE ?
         ORDER BY $sort ASC"
    );
    $search_param = '%' . $q . '%';
    $stmt->execute([$search_param, $search_param]);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>
<div class="card">
  <h1>Recherche</h1>
  <form method="GET">
    <div style="display:flex;gap:10px;margin-bottom:14px">
      <?php
      // FAILLE 3 : XSS reflechi sur l'affichage du terme de recherche (OWASP A03:2021)
      // <?= $q ?> et value="<?= $q ?>" affichent la valeur sans echappement.
      // En forgant un lien avec un script dans $q, le JS s'execute chez la victime.
      // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
      //
      // Ancien code vulnerable : value="<?= $q ?>"
      ?>
      <input type="text" name="q" value="<?= htmlspecialchars($q, ENT_QUOTES, 'UTF-8') ?>" placeholder="Rechercher un produit..." style="margin:0">
      <select name="sort" style="width:auto;margin:0">
        <option value="name"  <?= $sort==='name' ?'selected':'' ?>>Nom</option>
        <option value="price" <?= $sort==='price'?'selected':'' ?>>Prix</option>
      </select>
      <button class="btn" type="submit">Chercher</button>
    </div>
  </form>

  <?php if ($q !== ''): ?>
    <p style="font-size:13px;color:#888;margin-bottom:14px">
      <?= count($results) ?> résultat(s) pour : <?= htmlspecialchars($q, ENT_QUOTES, 'UTF-8') ?>
    </p>
    <?php if ($results): ?>
    <div class="grid">
      <?php foreach ($results as $p): ?>
      <div class="product-card">
        <h2><?= htmlspecialchars($p['name']) ?></h2>
        <div class="price"><?= number_format($p['price'],2) ?> EUR</div>
        <a href="product.php?id=<?= intval($p['id']) ?>" class="btn btn-sm">Voir</a>
      </div>
      <?php endforeach; ?>
    </div>
    <?php else: ?>
      <p style="color:#888">Aucun résultat.</p>
    <?php endif; ?>
  <?php endif; ?>
</div>
<?php require_once 'footer.php'; ?>
