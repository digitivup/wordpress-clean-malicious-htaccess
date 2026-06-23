# WordPress Clean Malicious htaccess
🧹 **A zero-false-positive PHP script to detect and bulk-remove malicious `.htaccess` files injected across a WordPress installation after a server compromise.**

---

## English 🇬🇧

`WordPress Clean Malicious htaccess` is a forensic cleanup tool built for WordPress administrators and agencies dealing with the aftermath of a server intrusion. When attackers gain access to a hosting account, they typically inject rogue `.htaccess` files across every subdirectory to maintain persistence or redirect traffic.

This script scans the entire WordPress directory tree and removes **only** the files that match the exact payload — byte for byte — using an MD5 hash fingerprint. Legitimate `.htaccess` files are never touched, even if they share some of the same rewrite rules.

### ✨ Features

* **Zero false positives:** Detection relies on an exact MD5 hash match combined with a file size pre-filter. A legitimate file with one extra comment or blank line will have a different hash and will not be deleted.
* **Dry-run mode by default:** The script simulates the cleanup and lists what would be deleted before anything is actually removed. Deletion requires an explicit flag.
* **Dual execution context:** Runs from the command line via SSH or directly from the browser for shared hosting environments without SSH access.
* **Recursive scan:** Uses PHP's `RecursiveDirectoryIterator` to walk the full directory tree, however deep.
* **Adaptable:** If the injected payload on your installation differs slightly, two constants at the top of the script are all you need to update.

### 🚀 Quick Start

**CLI (recommended):**

```bash
# Dry-run — lists matches, deletes nothing
php wordpress_clean_malicious_htaccess.php /path/to/wordpress

# Real deletion — only run after reviewing the dry-run output
php wordpress_clean_malicious_htaccess.php /path/to/wordpress --delete
```

**Browser (shared hosting without SSH):**

1. Upload the script to your WordPress root.
2. Open `https://yoursite.com/wordpress_clean_malicious_htaccess.php` — dry-run mode.
3. Open `https://yoursite.com/wordpress_clean_malicious_htaccess.php?delete=1` — real deletion.
4. **Delete the script from the server immediately after use.**

### 🔍 The targeted payload

The script targets `.htaccess` files containing the following injected content (MD5: `dfb6c253cac8782be9818ce68ae9970b`, 325 bytes):

```apache
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . index.php [L]
</IfModule>
<FilesMatch ".*\.(py|exe|phtml|php|PHP|Php|PHp|pHp|pHP|phP|PhP|php5|suspected)$">
Order Allow,Deny
Deny from all
</FilesMatch>
```

### 🔧 Adapting to a different payload

If the injected files on your installation differ slightly (whitespace, line endings, ordering), recalculate the fingerprint:

```bash
md5sum your_malicious_reference_file
wc -c your_malicious_reference_file
```

Then update the two constants at the top of the script:

```php
const MALICIOUS_MD5  = 'your_new_md5_hash';
const MALICIOUS_SIZE = 000; // bytes
```

### 📋 Requirements

* PHP 7.4 or higher
* Read access to the WordPress directory tree (write access required for deletion)

### 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## Français 🇫🇷

`WordPress Clean Malicious htaccess` est un outil de nettoyage forensique conçu pour les administrateurs WordPress et les agences qui gèrent les suites d'une intrusion serveur. Lorsque des attaquants accèdent à un hébergement, ils injectent typiquement des fichiers `.htaccess` malveillants dans chaque sous-répertoire pour maintenir leur persistance ou rediriger le trafic.

Ce script parcourt l'intégralité de l'arborescence WordPress et supprime **uniquement** les fichiers correspondant exactement au payload connu — octet pour octet — grâce à une empreinte MD5. Les fichiers `.htaccess` légitimes ne sont jamais touchés, même s'ils partagent certaines règles de réécriture identiques.

### ✨ Fonctionnalités

* **Zéro faux positif :** La détection repose sur une correspondance MD5 exacte combinée à un pré-filtre sur la taille du fichier. Un fichier légitime avec un commentaire ou une ligne vide supplémentaire aura un hash différent et ne sera pas supprimé.
* **Mode simulation par défaut :** Le script liste les correspondances sans rien supprimer. La suppression réelle nécessite un flag explicite.
* **Double contexte d'exécution :** Fonctionne en ligne de commande via SSH ou directement depuis le navigateur pour les hébergements mutualisés sans accès SSH.
* **Scan récursif :** Utilise le `RecursiveDirectoryIterator` de PHP pour parcourir l'arborescence complète, quelle que soit sa profondeur.
* **Adaptable :** Si le payload injecté sur votre installation diffère légèrement, deux constantes en tête de script suffisent à reconfigurer la détection.

### 🚀 Démarrage rapide

**CLI (recommandé) :**

```bash
# Simulation — liste les correspondances sans rien supprimer
php wordpress_clean_malicious_htaccess.php /chemin/vers/wordpress

# Suppression réelle — uniquement après vérification du dry-run
php wordpress_clean_malicious_htaccess.php /chemin/vers/wordpress --delete
```

**Navigateur (hébergement mutualisé sans SSH) :**

1. Déposez le script à la racine WordPress.
2. Ouvrez `https://votresite.fr/wordpress_clean_malicious_htaccess.php` — mode simulation.
3. Ouvrez `https://votresite.fr/wordpress_clean_malicious_htaccess.php?delete=1` — suppression réelle.
4. **Supprimez le script du serveur immédiatement après utilisation.**

### 🔍 Le payload ciblé

Le script cible les fichiers `.htaccess` contenant le contenu injecté suivant (MD5 : `dfb6c253cac8782be9818ce68ae9970b`, 325 octets) :

```apache
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . index.php [L]
</IfModule>
<FilesMatch ".*\.(py|exe|phtml|php|PHP|Php|PHp|pHp|pHP|phP|PhP|php5|suspected)$">
Order Allow,Deny
Deny from all
</FilesMatch>
```

### 🔧 Adapter à un payload différent

Si les fichiers injectés sur votre installation diffèrent légèrement (espaces, fins de ligne, ordre des blocs), recalculez l'empreinte :

```bash
md5sum votre_fichier_malveillant_de_reference
wc -c votre_fichier_malveillant_de_reference
```

Puis mettez à jour les deux constantes en tête de script :

```php
const MALICIOUS_MD5  = 'votre_nouveau_hash_md5';
const MALICIOUS_SIZE = 000; // octets
```

### 📋 Prérequis

* PHP 7.4 ou supérieur
* Accès en lecture à l'arborescence WordPress (accès en écriture requis pour la suppression)

### 📄 Licence

Ce projet est distribué sous licence **MIT** — voir le fichier [LICENSE](LICENSE) pour les détails.

---

Made by [Digitivup](https://digitivup.com) — Agence WordPress spécialisée.
