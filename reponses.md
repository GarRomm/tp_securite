# Corrections de sécurité — VulnShop

Récap de toutes les failles corrigées, fichier par fichier.
Les numéros de lignes correspondent au fichier corrigé.

---

## header.php

### session_start() sans options de sécurité — A07:2021

Sans config, le cookie de session est lisible par JS, transmissible cross-site, et l'ID peut passer dans l'URL.

**Correction (L11-15)** — 4 options avant `session_start()` :
- `cookie_httponly` : JS ne peut plus lire le cookie → XSS ne vole plus la session
- `cookie_samesite Strict` : cookie bloqué sur les requêtes cross-site → protection CSRF
- `use_strict_mode` : IDs de session forgés par l'attaquant rejetés
- `use_only_cookies` : ID de session interdit dans l'URL

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

---

## logout.php

### session_start() sans options de sécurité — A07:2021

Même problème que header.php.

**Correction (L7)** — `secure_session_start()` définie dans init.php, applique les mêmes options avant de démarrer la session.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

---

## init.php

### Faille 1 — Mots de passe hachés en MD5 — A02:2021

MD5 est rapide par conception : les hashs des comptes de démo se craquent en quelques secondes sur crackstation.net ou avec du matériel dédié.

**Correction (L73-77)** — `password_hash($pass, PASSWORD_BCRYPT)`. BCrypt est lent par design et intègre un sel aléatoire automatique, ce qui rend le cassage en masse inutilisable même avec des rainbow tables.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### Faille 2 — session_start() sans options dans api.php et logout.php — A07:2021

Ces fichiers appelaient `session_start()` brut.

**Correction (L149-157)** — Fonction `secure_session_start()` centralisée ici : httponly, samesite, strict_mode, only_cookies, puis `session_start()`. Un seul endroit à maintenir.

**Bonus (L119-137)** — Ajout de `csrf_token()`, `csrf_field()` et `csrf_check()` pour protéger tous les formulaires POST.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

---

## login.php

### Faille 1 — Injection SQL — A03:2021

`$username` collé directement dans la requête. Saisir `' OR '1'='1` bypasse l'authentification sans mot de passe.

**Correction (L21-23)** — Requête préparée avec `?` + `execute([$username])`.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 2 — MD5 pour la vérification du mot de passe — A02:2021

`md5($password)` injecté directement dans la requête SQL : deux failles en une ligne.

**Correction (L34)** — `password_verify($password, $user['password'])` côté PHP après récupération du compte par username seul.

**Bonus (L36)** — `session_regenerate_id(true)` après login pour bloquer la fixation de session.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### Faille 3 — Credentials en clair dans le HTML — A07:2021

`alice/alice123`, `bob/bob123`, `admin/admin` affichés dans la page. Visible en F12 par n'importe qui.

**Correction** — Code HTML supprimé. Les credentials sont conservés dans le README uniquement pour l'installation du TP, avec une mention explicite.

Réf. OWASP : https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

---

## register.php

### MD5 pour le stockage du mot de passe — A02:2021

Même problème que login.php.

**Correction (L20-27)** — `password_hash($p, PASSWORD_BCRYPT)` + validation longueur minimale 8 caractères.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

## admin.php

### Faille 1 — Contrôle d'accès cassé — A01:2021

L'ancien code affichait un message d'erreur mais continuait l'exécution. N'importe qui pouvait POST les actions admin.

**Correction (L17-20)** — `exit` après le message d'erreur + inclusion footer.php. Le script s'arrête vraiment.

Réf. OWASP : https://owasp.org/Top10/A01_2021-Broken_Access_Control/

### Faille 2 — Injection SQL dans toutes les actions admin — A03:2021

Toutes les actions injectaient les variables directement dans les requêtes.

**Correction** :
- `delete_user` (L35-38) : `intval()` + requête préparée
- `set_role` (L44-48) : `intval()` + liste blanche `['user', 'admin']` + requête préparée
- `delete_product` (L52-54) : `intval()` + requête préparée
- `delete_review` (L57-59) : `intval()` + requête préparée
- `add_balance` (L63-67) : `intval()` + `floatval()` + requête préparée

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 3 — Hash MD5 affiché dans le tableau HTML — A02:2021

La colonne `password` était affichée dans l'interface admin. Un hash MD5 se craque hors ligne en quelques secondes : l'exposer dans une UI accélère l'attaque.

**Correction** — Colonne `password` retirée du tableau.

Réf. OWASP : https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

### Faille 4 — XSS stocké dans les avis — A03:2021

`<?= $rv['content'] ?>` sans échappement. Un avis avec `<script>` vole la session de l'admin qui consulte le dashboard.

**Correction (L167)** — `echo htmlspecialchars($rv['content'], ENT_QUOTES, 'UTF-8')`.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

## api.php

### Faille 1 — API entière sans authentification — A01:2021

Aucune session, aucune vérification. Lecture des hashs, virements, suppression d'avis : tout était ouvert.

**Correction (L13)** — `secure_session_start()` en tête de fichier. Chaque action sensible vérifie ensuite `$me` avant d'agir.

Réf. OWASP : https://owasp.org/Top10/A01_2021-Broken_Access_Control/

### Faille 2 — Injection SQL dans la recherche — A03:2021

`$q` injecté dans `LIKE '%$q%'`. Une attaque UNION permettait de lire la table `users` (hashs MD5) sans être connecté.

**Correction (L36-38)** — Requête préparée + `SELECT` limité aux colonnes utiles, plus de `SELECT *`.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 3 — Injection SQL + exposition de données sensibles sur /user — A03:2021

`$id` injecté directement + `SELECT *` retournait le hash MD5 dans la réponse JSON.

**Correction (L59-61)** — `intval($id)` + requête préparée + `SELECT id, username, role` uniquement.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 4 — Dump de tous les hashs sans auth — A02:2021 + A01:2021

`SELECT *` sur `users` retournait tous les hashs MD5 à n'importe qui.

**Correction (L70-74)** — Vérification connexion + rôle admin + `SELECT id, username, email, role, balance` (sans `password`).

Réf. OWASP : https://owasp.org/Top10/A01_2021-Broken_Access_Control/

### Faille 5 — IDOR sur les commandes — A01:2021 + A03:2021

N'importe qui pouvait lire les commandes de n'importe quel user en passant l'uid de son choix.

**Correction (L89-94)** — Vérification connexion + `$me['id'] === $uid` (sauf admins) + `intval()` + requête préparée.

Réf. OWASP : https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference

### Faille 6 — Virement sans authentification — A01:2021

POST sur /transfer sans être connecté = virement entre n'importe quels comptes.

**Correction (L113-126)** — Vérification connexion + rôle admin + token CSRF via `hash_equals()` (protection timing attack) + `intval()`/`floatval()` + requêtes préparées.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

### Faille 7 — Suppression d'avis sans auth — A01:2021

DELETE sur les avis d'un produit ouvert à tous.

**Correction (L141-143)** — Vérification connexion + rôle admin + `intval()` + requête préparée.

Réf. OWASP : https://owasp.org/Top10/A01_2021-Broken_Access_Control/

### Faille 8 — Endpoint raw_query : SQL brut exécutable par tous — A03:2021

`?action=raw_query&sql=DROP TABLE users` fonctionnait depuis n'importe quel navigateur. Accès direct à la BDD pour tout le monde.

**Correction** — Endpoint supprimé. Pour déboguer une BDD en dev, utiliser DBeaver ou DB Browser en local.

Ancien code conservé en commentaire (L157-164) à titre pédagogique.

Réf. OWASP : https://owasp.org/Top10/A03_2021-Injection/

---

## profile.php

### Faille 1 — Injection SQL via $uid — A03:2021

`$uid` venait de `$_GET` et était collé directement dans la requête.

Note : la consultation d'un profil par uid reste publique par design (feature normale). Ce qui est protégé, c'est l'écriture : update/password/delete sont restreints au propriétaire via `$is_own`. La vraie faille ici, c'est l'injection SQL.

**Correction (L17-21)** — `intval($_GET['uid'])` + requête préparée.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 2 — Injection SQL en UPDATE — A03:2021

Mettre `', role='admin' WHERE id=1--` dans le champ bio suffisait pour devenir admin.

**Correction (L46)** — Requête préparée avec `?` pour bio, email et l'ID.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 3 — MD5 sur le changement de mot de passe — A02:2021

`md5()` + minimum 4 caractères seulement.

**Correction (L55-61)** — `password_hash($np, PASSWORD_BCRYPT)` + minimum 8 caractères + requête préparée.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### Faille 4 — XSS stocké dans la bio — A03:2021

`<?= $user['bio'] ?>` sans échappement. Un script en bio s'exécute chez chaque visiteur du profil.

**Correction (L101-103)** — `echo htmlspecialchars($user['bio'], ENT_QUOTES, 'UTF-8')`.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

## messages.php

### Faille 1 — Injection SQL sur le destinataire + inbox/sent — A03:2021

`$to_name` injecté directement → attaque UNION possible. Les requêtes inbox et sent utilisaient aussi `$me['id']` dans des requêtes dynamiques.

**Correction (L22-24)** — Requête préparée pour le destinataire. Les deux requêtes inbox (L31-39) et sent (L43-51) sont aussi préparées avec `execute([$me['id']])`.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 2 — XSS stocké dans les messages — A03:2021

`<?= $m['content'] ?>` sans échappement dans l'inbox et les envoyés. Un message avec du JS s'exécute chez le destinataire. Si c'est un admin, l'attaquant obtient sa session.

**Correction (L86 et L107)** — `echo htmlspecialchars($m['content'], ENT_QUOTES, 'UTF-8')` dans les deux boucles.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

## product.php

### Faille 1 — Injection SQL via l'ID produit — A03:2021

`$id` de `$_GET` injecté brut dans la requête. UNION possible pour lire d'autres tables.

**Correction (L14-22)** — `intval($_GET['id'])` + requête préparée.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 2 — Injection SQL via le code promo — A03:2021

Saisir `' OR '1'='1` comme code promo = réduction garantie sans code valide.

**Correction (L50-55)** — Requête préparée pour la vérification + requête préparée pour marquer le coupon utilisé.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 3 — Injection SQL dans les UPDATE solde/stock — A03:2021

`$total`, `$me['id']`, `$qty` et `$id` injectés directement dans les UPDATE.

**Correction (L72-75)** — Deux requêtes préparées séparées pour déduire le solde et le stock.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 4 — XSS stocké dans les avis — A03:2021

`<?= $rv['content'] ?>` sans échappement. Un script en avis s'exécute chez chaque visiteur de la page produit.

**Correction (L150)** — `echo htmlspecialchars($rv['content'], ENT_QUOTES, 'UTF-8')`.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

## search.php

### Faille 1 — Injection SQL dans le WHERE — A03:2021

`$q` injecté dans `LIKE '%$q%'`. Attaque UNION pour lire `users` et récupérer les mots de passe.

**Correction (L36-40)** — Requête préparée avec deux `?` pour les deux clauses LIKE.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### Faille 2 — Injection SQL dans ORDER BY — A03:2021

`ORDER BY $sort` : les requêtes préparées ne protègent pas les noms de colonnes. `$sort` contrôlé par l'utilisateur = injection dans ORDER BY.

**Correction (L30-33)** — Liste blanche `['name', 'price']`. Si `$sort` n'est pas dedans, on force `name`. On insère ensuite la valeur validée directement dans la chaîne (seule option possible pour un nom de colonne).

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

### Faille 3 — XSS réfléchi sur le terme de recherche — A03:2021

`value="<?= $q ?>"` et `<?= $q ?>` non échappés. Forger un lien avec un script dans `$q` = JS exécuté chez la victime qui clique.

**Correction (L57 et L63)** — `htmlspecialchars($q, ENT_QUOTES, 'UTF-8')` dans l'attribut `value` et dans le texte de résultats.

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

## sell.php

### Faille 1 — Upload de fichier arbitraire — A04:2021

`$_FILES['image']['name']` utilisé directement comme nom de fichier, sans aucune validation. Uploader `shell.php` puis appeler `/uploads/shell.php` = RCE (Remote Code Execution).

**Correction (L32-57)** :
- Limite taille à 2 Mo
- Liste blanche sur l'extension : jpg, jpeg, png, gif, webp
- Vérification du type MIME réel avec `finfo` (pas juste l'extension déclarée)
- Nom de fichier généré aléatoirement avec `bin2hex(random_bytes(16))` : zéro contrôle côté utilisateur sur le nom final
- Création automatique du dossier `/uploads/` avec `mkdir()` s'il n'existe pas (permissions 755)

Réf. OWASP : https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### Faille 2 — Injection SQL + IDOR sur la suppression — A03:2021 + A01:2021

`$pid` injecté directement + aucune vérification que le produit appartient au vendeur connecté. N'importe quel vendeur pouvait supprimer les produits des autres.

**Correction (L79-81)** — `intval($pid)` + requête préparée + `AND seller_id=?`. Si le produit n'appartient pas au vendeur, la requête ne supprime rien.

Réf. OWASP : https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference

### Faille 3 — Injection SQL + IDOR sur la mise à jour du prix — A03:2021 + A01:2021

Même double faille que la suppression.

**Correction (L97-101)** — `intval($pid)` + `floatval($newprice)` + requête préparée + `AND seller_id=?` + validation prix strictement positif.

Réf. OWASP : https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference

---

## Résumé OWASP

| Catégorie | Fichiers |
|---|---|
| A01:2021 — Broken Access Control | admin.php, api.php, profile.php, sell.php, messages.php |
| A02:2021 — Cryptographic Failures | init.php, login.php, register.php, profile.php, admin.php |
| A03:2021 — Injection (SQL + XSS) | Tous les fichiers |
| A04:2021 — Insecure Design | sell.php |
| A07:2021 — Auth Failures | header.php, logout.php, init.php, login.php |
