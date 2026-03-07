<?php
$title = 'Connexion';
require_once 'header.php';

csrf_check();

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // FAILLE 1 : Injection SQL (OWASP A03:2021 - Injection)
    // $username colle directement dans la requete. En saisissant ' OR '1'='1
    // la condition devient toujours vraie : connexion sans mot de passe.
    // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
    //
    // Ancien code vulnerable :
    // $query = "SELECT * FROM users WHERE username='$username' AND password='" . md5($password) . "'";
    // $user  = db()->query($query)->fetch(PDO::FETCH_ASSOC);

    $stmt = db()->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // FAILLE 2 : Mot de passe hache avec MD5 (OWASP A02:2021 - Cryptographic Failures)
    // md5() est rapide et craquable en secondes. La verification etait aussi faite
    // directement dans la requete SQL, combinant les deux failles.
    // Source OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    //
    // Ancien code vulnerable : verification via md5() dans la requete SQL ci-dessus.

    if ($user && password_verify($password, $user['password'])) {
        // Regenerer l'ID de session apres connexion empeche la fixation de session
        session_regenerate_id(true);
        $_SESSION['uid'] = $user['id'];
        header('Location: index.php');
        exit;
    } else {
        // Message volontairement vague : ne pas distinguer "mauvais user" de "mauvais mdp"
        // pour empecher l'enumeration des comptes existants.
        $error = "Identifiants incorrects.";
    }
}
?>
<div class="card" style="max-width:400px;margin:0 auto">
  <h1>Connexion</h1>
  <?php if ($error): ?><div class="err"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <form method="POST">
    <?php echo csrf_field(); ?>
    <label style="font-size:13px">Nom d'utilisateur</label>
    <input type="text" name="username" autocomplete="username">
    <label style="font-size:13px">Mot de passe</label>
    <input type="password" name="password" autocomplete="current-password">
    <button class="btn" style="width:100%" type="submit">Se connecter</button>
  </form>
  <hr>
  <p style="font-size:13px;color:#888;text-align:center">
    Pas de compte ? <a href="register.php">S'inscrire</a>
  </p>

  <?php
  // FAILLE 3 : Credentials exposes dans le HTML (OWASP A07:2021)
  // Les identifiants de tous les comptes etaient affiches en clair dans la page,
  // visibles par n'importe qui avec F12. Supprimes. En dev, utiliser un .env local.
  // Source OWASP : https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  //
  // Ancien code vulnerable :
  // <p>alice/alice123 - bob/bob123 - admin/admin</p>
  ?>
</div>
<?php require_once 'footer.php'; ?>
