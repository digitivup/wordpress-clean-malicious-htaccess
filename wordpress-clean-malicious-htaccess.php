<?php
// ==============================================================================
// wordpress_clean_malicious_htaccess.php
// WordPress Clean Malicious htaccess — by Digitivup
// https://github.com/digitivup/wordpress-clean-malicious-htaccess
//
// Suppression des .htaccess malveillants injectés post-intrusion.
// Détection par hash MD5 exact — aucun faux positif possible.
// ==============================================================================
// Usage CLI :
//   Simulation  : php wordpress_clean_malicious_htaccess.php /chemin/wordpress
//   Suppression : php wordpress_clean_malicious_htaccess.php /chemin/wordpress --delete
//
// Usage navigateur :
//   Déposer le fichier à la racine WordPress, ouvrir dans le navigateur.
//   Ajouter ?delete=1 dans l'URL pour activer la suppression réelle.
//   SUPPRIMER LE FICHIER du serveur immédiatement après utilisation.
// ==============================================================================

// --- Empreinte du payload malveillant exact ---
// Recalculer si nécessaire : md5sum fichier_reference
const MALICIOUS_MD5  = 'dfb6c253cac8782be9818ce68ae9970b';
const MALICIOUS_SIZE = 325; // octets — pré-filtre rapide avant le MD5

// ==============================================================================
// Détection du contexte d'exécution
// ==============================================================================

$isCli      = (php_sapi_name() === 'cli');
$isDryRun   = true;
$searchRoot = __DIR__;

if ($isCli) {
    $opts     = getopt('', ['delete']);
    $isDryRun = !isset($opts['delete']);
    foreach (array_slice($argv, 1) as $arg) {
        if ($arg !== '--delete' && is_dir($arg)) {
            $searchRoot = realpath($arg);
            break;
        }
    }
} else {
    $isDryRun   = !isset($_GET['delete']) || $_GET['delete'] !== '1';
    $searchRoot = realpath(__DIR__);
    header('Content-Type: text/plain; charset=utf-8');
}

// ==============================================================================
// Fonctions utilitaires
// ==============================================================================

function output(string $line): void
{
    echo $line . "\n";
    if (php_sapi_name() !== 'cli') {
        ob_flush();
        flush();
    }
}

/**
 * Parcours récursif via SPL — fiable sur de grandes arborescences.
 *
 * @return Generator<SplFileInfo>
 */
function findHtaccess(string $root): Generator
{
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getFilename() === '.htaccess') {
            yield $file;
        }
    }
}

// ==============================================================================
// En-tête
// ==============================================================================

output('');
output('================================================================');
output('  WordPress Clean Malicious htaccess — Digitivup');
output('  https://github.com/digitivup/wordpress-clean-malicious-htaccess');
output('================================================================');
output('  Répertoire analysé : ' . $searchRoot);
output('  Hash MD5 ciblé     : ' . MALICIOUS_MD5);
output('  Mode               : ' . ($isDryRun ? 'SIMULATION — aucune suppression' : 'SUPPRESSION RÉELLE'));
if ($isCli && $isDryRun) {
    output('  Pour supprimer     : php ' . basename(__FILE__) . ' "' . $searchRoot . '" --delete');
} elseif (!$isCli && $isDryRun) {
    output('  Pour supprimer     : ajouter ?delete=1 dans l\'URL');
}
output('----------------------------------------------------------------');
output('');

// ==============================================================================
// Parcours et traitement
// ==============================================================================

$scanned = 0;
$found   = 0;
$deleted = 0;
$errors  = 0;

foreach (findHtaccess($searchRoot) as $file) {
    $scanned++;
    $path = $file->getPathname();

    // Pré-filtre taille (évite un md5_file inutile)
    if ($file->getSize() !== MALICIOUS_SIZE) {
        continue;
    }

    // Vérification hash MD5 exact
    $hash = md5_file($path);
    if ($hash !== MALICIOUS_MD5) {
        continue;
    }

    // Correspondance exacte confirmée
    $found++;

    if ($isDryRun) {
        output('  [DRY-RUN]  ' . $path);
    } else {
        if (@unlink($path)) {
            output('  [SUPPRIMÉ] ' . $path);
            $deleted++;
        } else {
            output('  [ERREUR]   Impossible de supprimer : ' . $path);
            $errors++;
        }
    }
}

// ==============================================================================
// Résumé
// ==============================================================================

output('');
output('----------------------------------------------------------------');
output('  .htaccess scannés  : ' . $scanned);
output('  Correspondances    : ' . $found);

if ($isDryRun) {
    if ($found > 0) {
        output('');
        output('  Aucune suppression effectuée (dry-run).');
        if ($isCli) {
            output('  Commande pour supprimer :');
            output('  php ' . basename(__FILE__) . ' "' . $searchRoot . '" --delete');
        } else {
            output('  Ajouter ?delete=1 dans l\'URL pour supprimer.');
        }
    } else {
        output('  Aucun fichier malveillant détecté.');
    }
} else {
    output('  Supprimés          : ' . $deleted);
    if ($errors > 0) {
        output('  Erreurs            : ' . $errors);
    }
}

output('================================================================');
output('');
