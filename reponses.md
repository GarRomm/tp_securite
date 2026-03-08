# Réponses — Corrections de sécurité VulnShop

Ce fichier récapitule toutes les failles corrigées dans le projet, fichier par fichier.
Pour chaque correction, les numéros de lignes indiqués correspondent au fichier tel qu'il est maintenant (après correction).

---

## header.php

### Faille (L2) — Session sans options de sécurité (OWASP A07:2021)

Le `session_start()` de base ne configurait rien. Du coup le cookie de session était lisible par JavaScript, pouvait être envoyé vers des sites tiers, et l'ID de session pouvait même passer dans l'URL.

**Correction (L11-15)** : avant d'appeler `session_start()`, on configure maintenant les options critiques :
- `cookie_httponly` : le cookie ne peut plus être lu par JavaScript, donc un XSS ne peut plus voler la session directement
- `cookie_samesite Strict` : le cookie n'est pas envoyé si la requête vient d'un autre site (protection CSRF)
- `use_strict_mode` : les IDs de session inventés par l'attaquant sont refusés
- `use_only_cookies` : l'ID de session ne peut plus passer en paramètre GET dans l'URL

---

## logout.php

### Faille (L2) — session_start() sans options de sécurité (OWASP A07:2021)

Même problème que header.php : le `session_start()` brut ne configurait rien.

**Correction (L7)** : utilisation de `secure_session_start()` définie dans init.php, qui applique les mêmes options de sécurité que dans header.php avant de démarrer la session.

---

## init.php

### Faille 1 (L63) — Mots de passe hachés avec MD5 (OWASP A02:2021)

Les mots de passe des comptes de démo étaient stockés avec `md5()`. MD5 est conçu pour être rapide : un attaquant qui vole la base de données retrouve les mots de passe en quelques secondes via des rainbow tables ou du matériel dédié.

**Correction (L73-77)** : remplacement de `md5()` par `password_hash($pass, PASSWORD_BCRYPT)`. BCrypt est lent par conception et intègre automatiquement un sel aléatoire, ce qui rend le cassage en masse impossible même avec les bases de hashs connues.

### Faille 2 (L139) — session_start() sans options de sécurité dans api.php et logout.php (OWASP A07:2021)

Ces deux fichiers appelaient `session_start()` directement sans aucune option.

**Correction (L149-157)** : ajout de la fonction `secure_session_start()` qui centralise la configuration de sécurité de session (httponly, samesite, strict_mode, only_cookies) puis appelle `session_start()`. Tous les points d'entrée utilisent maintenant cette fonction.

**Bonus** : ajout des fonctions `csrf_token()`, `csrf_field()` et `csrf_check()` (L119-137) pour la protection CSRF sur tous les formulaires.

---

## login.php

### Faille 1 (L13) — Injection SQL (OWASP A03:2021)

Le `$username` était collé directement dans la requête SQL. En saisissant `' OR '1'='1`, la condition devenait toujours vraie et on se connectait sans mot de passe.

**Correction (L21-23)** : requête préparée avec un `?` et `execute([$username])`. Le username n'est plus jamais interprété comme du SQL.

### Faille 2 (L26) — Mot de passe haché avec MD5 (OWASP A02:2021)

La vérification utilisait `md5($password)` directement dans la requête SQL, combinant la faille d'injection et la faille cryptographique en une seule ligne.

**Correction (L34)** : `password_verify($password, $user['password'])`. On récupère d'abord le compte par username seul, puis on vérifie le mot de passe côté PHP avec BCrypt.

**Bonus (L36)** : `session_regenerate_id(true)` après connexion réussie pour empêcher la fixation de session.

### Faille 3 (L63) — Credentials exposés dans le HTML (OWASP A07:2021)

Les identifiants de tous les comptes (`alice/alice123`, `bob/bob123`, `admin/admin`) étaient affichés en clair dans la page de connexion. Visible à tout le monde avec F12.

**Correction** : commentaire conservé pour montrer ce qui a été supprimé, mais le code HTML qui affichait les credentials a été retiré.

---

## register.php

### Faille (L16) — Mot de passe haché avec MD5 (OWASP A02:2021)

Même problème que login.php : l'inscription stockait le mot de passe avec `md5()`.

**Correction (L20-27)** : `password_hash($p, PASSWORD_BCRYPT)` à la place de `md5($p)`. En plus, ajout d'une validation de longueur minimale de 8 caractères avant de hacher.

---

## admin.php

### Faille 1 (L6) — Contrôle d'accès cassé (OWASP A01:2021)

L'ancien code affichait un message d'erreur si l'utilisateur n'était pas admin, mais continuait l'exécution quand même. N'importe qui pouvait donc envoyer des requêtes POST pour exécuter les actions d'administration.

**Correction (L17-20)** : ajout d'un `exit` après le message d'erreur + inclusion de footer.php pour ne pas laisser la page se charger partiellement. Le script s'arrête pour de vrai si ce n'est pas un admin.

### Faille 2 (L31) — Injection SQL dans toutes les actions admin (OWASP A03:2021)

Chaque action (`delete_user`, `set_role`, `delete_product`, `delete_review`, `add_balance`) insérait les variables directement dans les requêtes SQL sans aucune validation.

**Correction** :
- `delete_user` (L35-38) : `intval()` sur l'ID + requête préparée
- `set_role` (L44-48) : `intval()` + liste blanche sur `$role` (`['user', 'admin']`) + requête préparée
- `delete_product` (L52-54) : `intval()` + requête préparée
- `delete_review` (L57-59) : `intval()` + requête préparée
- `add_balance` (L63-67) : `intval()` + `floatval()` + requête préparée

### Faille 3 (L99) — Hash MD5 des mots de passe affiché dans le tableau HTML (OWASP A02:2021)

Le tableau des utilisateurs affichait la colonne `password` contenant les hashs MD5. Même si un hash n'est pas le mot de passe en clair, afficher les hashs MD5 dans l'interface facilite leur cassage hors ligne.

**Correction** : la colonne `password` a été retirée du tableau HTML. Un admin n'a aucune raison légitime de voir les hashs.

### Faille 4 (L162) — XSS stocké dans les avis (OWASP A03:2021)

`<?= $rv['content'] ?>` affichait le contenu des avis sans échappement. Un avis contenant `<script>` s'exécutait dans le navigateur de l'admin qui consultait ce tableau de bord, permettant de voler sa session.

**Correction (L167)** : `echo htmlspecialchars($rv['content'], ENT_QUOTES, 'UTF-8')`. Tous les caractères spéciaux HTML sont neutralisés avant l'affichage.

---

## api.php

### Faille 1 (L5) — API entière sans authentification (OWASP A01:2021)

Toutes les actions de l'API étaient accessibles sans être connecté. N'importe qui pouvait lire les données des utilisateurs, faire des virements, supprimer des avis.

**Correction (L13)** : ajout de `secure_session_start()` en haut du fichier. Chaque action qui nécessite une authentification vérifie maintenant `$me` (la session) avant de continuer.

### Faille 2 (L27) — Injection SQL dans la recherche (OWASP A03:2021)

`$q` était inséré directement dans la requête `LIKE '%$q%'`. Une attaque UNION permettait de lire n'importe quelle table, notamment les hashs de mots de passe, sans être connecté.

**Correction (L36-38)** : requête préparée avec `?` + SELECT limité aux colonnes utiles (plus de `SELECT *` qui exposait potentiellement d'autres données).

### Faille 3 (L47) — Injection SQL + exposition de données sensibles (OWASP A03:2021)

`$id` était inséré directement dans la requête. De plus, `SELECT *` retournait le hash MD5 du mot de passe dans la réponse JSON.

**Correction (L59-61)** : `intval($id)` + requête préparée + `SELECT id, username, role` uniquement, sans le mot de passe ni les données financières.

### Faille 4 (L65) — Exposition de tous les hashs sans authentification (OWASP A02:2021 + A01:2021)

`SELECT *` sur la table `users` retournait les hashs MD5 de tous les comptes sans aucune vérification d'identité.

**Correction (L70-74)** : vérification de connexion + vérification du rôle admin + `SELECT id, username, email, role, balance` sans `password`.

### Faille 5 (L83) — Injection SQL + IDOR sur les commandes (OWASP A03:2021 + A01:2021)

N'importe qui pouvait voir les commandes de n'importe quel utilisateur en passant n'importe quel `uid`.

**Correction (L89-94)** : vérification de connexion + vérification que `$me['id'] === $uid` (sauf pour les admins) + `intval()` + requête préparée.

### Faille 6 (L104) — Virement d'argent sans authentification (OWASP A01:2021)

N'importe qui pouvait virer de l'argent entre n'importe quels comptes avec un simple POST.

**Correction (L113-126)** : vérification de connexion + vérification du rôle admin + vérification du token CSRF (`hash_equals`) + `intval()` et `floatval()` sur les IDs et le montant + requêtes préparées.

### Faille 7 (L135) — Suppression d'avis sans authentification (OWASP A01:2021)

N'importe qui pouvait supprimer tous les avis d'un produit.

**Correction (L141-143)** : vérification de connexion + vérification du rôle admin + `intval()` + requête préparée.

### Faille 8 (L150) — Endpoint `raw_query` : exécution directe de SQL brut (OWASP A03:2021)

C'était l'équivalent d'un accès direct à la base de données pour tout le monde. On pouvait envoyer `?action=raw_query&sql=DROP TABLE users` depuis n'importe quel navigateur.

**Correction** : l'endpoint a été complètement supprimé. Le code commenté est conservé en L157-164 pour montrer ce qui existait.

---

## profile.php

### Faille 1 (L8) — IDOR + Injection SQL via `$uid` (OWASP A01:2021 + A03:2021)

`$uid` venait de `$_GET` sans validation. Un attaquant pouvait accéder au profil de n'importe qui en devinant un ID, et en plus injecter du SQL.

**Correction (L15-18)** : `intval($_GET['uid'])` + requête préparée. Plus possible d'injecter, et les IDs sont forcément des entiers.

### Faille 2 (L35) — Injection SQL en UPDATE (OWASP A03:2021)

En mettant `', role='admin' WHERE id=1--` dans le champ bio, la requête était détournée pour modifier le rôle de n'importe quel compte.

**Correction (L46)** : requête préparée avec `?` pour bio, email et l'ID. Les valeurs ne sont plus jamais interprétées comme du SQL.

### Faille 3 (L52) — Mot de passe haché avec MD5 lors du changement (OWASP A02:2021)

Le changement de mot de passe utilisait `md5()` comme les autres failles, et acceptait des mots de passe de 4 caractères minimum seulement.

**Correction (L55-61)** : `password_hash($np, PASSWORD_BCRYPT)` + longueur minimum portée à 8 caractères + requête préparée.

### Faille 4 (L97) — XSS stocké dans la bio (OWASP A03:2021)

`<?= $user['bio'] ?>` affichait la bio sans échappement. Un script sauvegardé en bio s'exécutait dans le navigateur de tout visiteur du profil.

**Correction (L101-103)** : `echo htmlspecialchars($user['bio'], ENT_QUOTES, 'UTF-8')`.

---

## messages.php

### Faille 1 (L15) — Injection SQL dans la recherche du destinataire (OWASP A03:2021)

`$to_name` inséré directement permettait une attaque UNION pour lire d'autres tables en envoyant un message à un destinataire forgé.

**Correction (L22-24)** : requête préparée avec `?` pour le username du destinataire.

Les requêtes inbox (L31-39) et sent (L43-51) utilisaient aussi `$me['id']` directement dans des requêtes dynamiques.

**Correction** : les deux requêtes sont maintenant des requêtes préparées avec `execute([$me['id']])`.

### Faille 2 (L82) — XSS stocké dans les messages (OWASP A03:2021)

`<?= $m['content'] ?>` affichait le contenu des messages sans échappement dans l'inbox et les messages envoyés. Un message contenant du JavaScript s'exécutait chez le destinataire. Si la victime est admin, l'attaquant obtient un accès total.

**Correction (L86 et L107)** : `echo htmlspecialchars($m['content'], ENT_QUOTES, 'UTF-8')` dans les deux boucles d'affichage.

---

## product.php

### Faille 1 (L7) — Injection SQL via l'ID du produit (OWASP A03:2021)

`$id` venait directement de `$_GET` et était inséré brut dans la requête. Une attaque UNION permettait de lire d'autres tables.

**Correction (L14-22)** : `intval($_GET['id'])` + requête préparée.

### Faille 2 (L41) — Injection SQL via le code promo (OWASP A03:2021)

En saisissant `' OR '1'='1` comme code promo, la condition devenait toujours vraie et on obtenait une réduction sans code valide.

**Correction (L50-55)** : requête préparée + `execute([$coupon])`. La mise à jour du coupons (marquer comme utilisé) est aussi préparée.

### Faille 3 (L66) — Injection SQL dans les UPDATE de solde et stock (OWASP A03:2021)

`$total`, `$me['id']`, `$qty` et `$id` étaient insérés directement dans les requêtes UPDATE.

**Correction (L72-75)** : deux requêtes préparées pour déduire le solde et le stock.

### Faille 4 (L146) — XSS stocké dans les avis (OWASP A03:2021)

`<?= $rv['content'] ?>` affichait le contenu des avis sans échappement. Un script dans un avis s'exécutait chez chaque visiteur de la page produit.

**Correction (L150)** : `echo htmlspecialchars($rv['content'], ENT_QUOTES, 'UTF-8')`.

---

## search.php

### Faille 1 (L11) — Injection SQL dans la clause WHERE (OWASP A03:2021)

`$q` inséré directement dans le `LIKE '%$q%'` permettait une attaque UNION pour récupérer les données de n'importe quelle table, y compris les mots de passe.

**Correction (L36-40)** : requête préparée avec deux `?` pour les deux clauses LIKE.

### Faille 2 (L16) — Injection SQL dans ORDER BY (OWASP A03:2021)

`ORDER BY $sort` est un cas particulier : les requêtes préparées ne protègent pas les noms de colonnes. `$sort` contrôlé par l'utilisateur permettait d'injecter du SQL dans la clause ORDER BY.

**Correction (L30-33)** : liste blanche `['name', 'price']`. Si `$sort` ne fait pas partie de la liste, il est remplacé par `name`. La valeur validée est ensuite insérée directement dans la chaîne de requête (seule solution acceptable ici puisqu'on ne peut pas paramétrer un nom de colonne).

### Faille 3 (L50) — XSS réfléchi sur le terme de recherche (OWASP A03:2021)

`value="<?= $q ?>"` et l'affichage du terme recherché (`<?= $q ?>`) n'étaient pas échappés. En forgeant un lien avec un script dans `$q`, le JavaScript s'exécutait chez la victime qui cliquait dessus.

**Correction (L57 et L63)** : `htmlspecialchars($q, ENT_QUOTES, 'UTF-8')` dans l'attribut `value` et dans le texte de résultats.

---

## sell.php

### Faille 1 (L23) — Upload de fichier arbitraire (OWASP A04:2021)
Ce fichier a été reconstruit après avoir été considéré comme une backdoor par mon système d'exploitation.
Le code original utilisait `$_FILES['image']['name']` directement comme nom de fichier sans aucune validation. Un attaquant pouvait uploader `shell.php` et l'exécuter via `/uploads/shell.php` pour prendre le contrôle du serveur (Remote Code Execution).

**Correction (L32-57)** :
- Limite de taille à 2 Mo
- Vérification de l'extension (liste blanche : jpg, jpeg, png, gif, webp)
- Vérification du type MIME réel du fichier avec `finfo` (pas seulement l'extension déclarée)
- Génération d'un nom de fichier aléatoire avec `bin2hex(random_bytes(16))` : l'utilisateur n'a aucun contrôle sur le nom final, impossible de placer un fichier à un emplacement prévisible

### Faille 2 (L71) — Injection SQL + IDOR sur la suppression de produit (OWASP A03:2021 + A01:2021)

`$pid` était inséré directement dans la requête, et surtout il n'y avait aucune vérification que le produit appartenait au vendeur connecté. N'importe quel vendeur pouvait supprimer les produits des autres.

**Correction (L79-81)** : `intval($pid)` + requête préparée + condition `AND seller_id=?` avec l'ID du vendeur connecté. Si le produit n'appartient pas à ce vendeur, la requête ne supprime rien.

### Faille 3 (L89) — Injection SQL + IDOR sur la mise à jour du prix (OWASP A03:2021 + A01:2021)

Même double faille que la suppression : `$newprice` et `$pid` insérés directement, sans vérification de propriété.

**Correction (L97-101)** : `intval($pid)` + `floatval($newprice)` + requête préparée + condition `AND seller_id=?`. Validation supplémentaire : le nouveau prix doit être strictement positif.

---

## Résumé des catégories OWASP corrigées

| Catégorie OWASP | Description | Fichiers concernés |
|---|---|---|
| A01:2021 — Broken Access Control | Contrôle d'accès cassé, IDOR, absence d'auth | admin.php, api.php, profile.php, sell.php |
| A02:2021 — Cryptographic Failures | MD5 pour les mots de passe | init.php, login.php, register.php, profile.php, admin.php |
| A03:2021 — Injection | Injection SQL, XSS stocké, XSS réfléchi | Tous les fichiers |
| A04:2021 — Insecure Design | Upload de fichier sans validation | sell.php |
| A07:2021 — Auth Failures | Session sans options de sécurité, credentials en dur | header.php, logout.php, init.php, login.php |
