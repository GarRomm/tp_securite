<?php
$title = 'Inscription';
require_once 'header.php';

csrf_check();

$error = $ok = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';
    $e = trim($_POST['email'] ?? '');

    if ($u && $p && $e) {

        // FAILLE : Mot de passe hache avec MD5 (OWASP A02:2021 - Cryptographic Failures)
        // md5() est rapide et craquable en secondes via Rainbow Tables.
        // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
        //
        // Ancien code vulnerable :
        // db()->prepare("INSERT INTO users (username,password,email) VALUES (?,?,?)")
        //    ->execute([$u, md5($p), $e]);

        if (mb_strlen($p) < 8) {
            $error = "Le mot de passe doit contenir au moins 8 caracteres.";
        } else {
            try {
                $hash = password_hash($p, PASSWORD_BCRYPT);
                db()->prepare("INSERT INTO users (username,password,email) VALUES (?,?,?)")
                   ->execute([$u, $hash, $e]);
                $ok = "Compte créé ! <a href='login.php'>Se connecter</a>";
            } catch (Exception $ex) {
                $error = "Ce nom d'utilisateur est déjà pris.";
            }
        }
    } else {
        $error = "Tous les champs sont obligatoires.";
    }
}
?>
<div class="card" style="max-width:400px;margin:0 auto">
  <h1>Inscription</h1>
  <?php if ($error): ?><div class="err"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <?php if ($ok):    ?><div class="ok"><?= $ok ?></div><?php endif; ?>
  <form method="POST">
    <?php echo csrf_field(); ?>
    <label style="font-size:13px">Nom d'utilisateur</label>
    <input type="text" name="username" autocomplete="username">
    <label style="font-size:13px">Email</label>
    <input type="email" name="email" autocomplete="email">
    <label style="font-size:13px">Mot de passe (8 caracteres minimum)</label>
    <input type="password" name="password" autocomplete="new-password">
    <button class="btn" style="width:100%" type="submit">Créer mon compte</button>
  </form>
</div>
<?php require_once 'footer.php'; ?>
