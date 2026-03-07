<?php
$title = 'Messages';
require_once 'header.php';
$me = require_login();

csrf_check();

$db = db();
$ok = $error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $to_name = trim($_POST['to'] ?? '');
    $content = $_POST['content'] ?? '';

    // FAILLE 1 : Injection SQL dans la recherche du destinataire (OWASP A03:2021)
    // $to_name insere directement permettait une attaque UNION pour lire d'autres tables.
    // Source OWASP : https://owasp.org/www-community/attacks/SQL_Injection
    //
    // Ancien code vulnerable :
    // $to = $db->query("SELECT * FROM users WHERE username='$to_name'")->fetch(PDO::FETCH_ASSOC);

    $stmt = $db->prepare("SELECT * FROM users WHERE username=?");
    $stmt->execute([$to_name]);
    $to = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$to) {
        $error = "Utilisateur introuvable.";
    } elseif (trim($content) !== '') {
        $db->prepare("INSERT INTO messages (from_id,to_id,content) VALUES (?,?,?)")
           ->execute([$me['id'], $to['id'], $content]);
        $ok = "Message envoyé à " . htmlspecialchars($to['username']) . ".";
    }
}

// Ancien code vulnerable :
// $inbox = $db->query("... WHERE m.to_id = " . $me['id'] . " ...)->fetchAll(...);

$stmt_inbox = $db->prepare(
    "SELECT m.*, u.username as sender FROM messages m
     JOIN users u ON m.from_id = u.id
     WHERE m.to_id = ?
     ORDER BY m.created_at DESC"
);
$stmt_inbox->execute([$me['id']]);
$inbox = $stmt_inbox->fetchAll(PDO::FETCH_ASSOC);

// Ancien code vulnerable :
// $sent = $db->query("... WHERE m.from_id = " . $me['id'] . " ...)->fetchAll(...);

$stmt_sent = $db->prepare(
    "SELECT m.*, u.username as recipient FROM messages m
     JOIN users u ON m.to_id = u.id
     WHERE m.from_id = ?
     ORDER BY m.created_at DESC"
);
$stmt_sent->execute([$me['id']]);
$sent = $stmt_sent->fetchAll(PDO::FETCH_ASSOC);
?>
<div class="card">
  <h1>Messagerie</h1>
  <?php if ($ok): ?><div class="ok"><?= htmlspecialchars($ok) ?></div><?php endif; ?>
  <?php if ($error): ?><div class="err"><?= htmlspecialchars($error) ?></div><?php endif; ?>

  <h2>Nouveau message</h2>
  <form method="POST">
    <?php echo csrf_field(); ?>
    <label style="font-size:13px">Destinataire (username)</label>
    <input type="text" name="to" placeholder="ex: alice">
    <label style="font-size:13px">Message</label>
    <textarea name="content" placeholder="Votre message..."></textarea>
    <button class="btn" type="submit">Envoyer</button>
  </form>
</div>

<div class="card">
  <h2>Boîte de réception (<?= count($inbox) ?>)</h2>
  <?php foreach ($inbox as $m): ?>
  <div style="border-bottom:1px solid #eee;padding:10px 0">
    <p class="meta"><strong><?= htmlspecialchars($m['sender']) ?></strong> — <?= htmlspecialchars($m['created_at']) ?></p>
    <div style="margin-top:6px">
      <?php
      // FAILLE 2 : XSS stocke dans les messages (OWASP A03:2021 - Stored XSS)
      // Un message contenant du JavaScript s'executait chez le destinataire, permettant
      // de voler sa session. Si la victime est admin, l'attaquant obtient un acces total.
      // Source OWASP : https://owasp.org/www-community/attacks/xss/#stored-xss-attacks
      //
      // Ancien code vulnerable : <?= $m['content'] ?>
      echo htmlspecialchars($m['content'], ENT_QUOTES, 'UTF-8');
      ?>
    </div>
  </div>
  <?php endforeach; ?>
  <?php if (!$inbox): ?><p style="color:#888">Aucun message reçu.</p><?php endif; ?>
</div>

<div class="card">
  <h2>Messages envoyés (<?= count($sent) ?>)</h2>
  <?php foreach ($sent as $m): ?>
  <div style="border-bottom:1px solid #eee;padding:10px 0">
    <p class="meta">À <strong><?= htmlspecialchars($m['recipient']) ?></strong> — <?= htmlspecialchars($m['created_at']) ?></p>
    <div style="margin-top:6px">
      <?php
      // Meme faille XSS stocke que ci-dessus.
      // Ancien code vulnerable : <?= $m['content'] ?>
      echo htmlspecialchars($m['content'], ENT_QUOTES, 'UTF-8');
      ?>
    </div>
  </div>
  <?php endforeach; ?>
  <?php if (!$sent): ?><p style="color:#888">Aucun message envoyé.</p><?php endif; ?>
</div>
<?php require_once 'footer.php'; ?>
