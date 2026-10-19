<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Security/SourcePolicy.php';

use Afara\Security\SourcePolicy;

$allowed = [
    ['wp-content/plugins/demo/src/Plugin.php', false],
    ['wp-content/themes/demo/assets/styles.css', false],
    ['wp-content/themes/demo', true],
];
$blocked = [
    ['wp-content/plugins/demo/.env', false],
    ['wp-content/plugins/demo/config.php', false],
    ['wp-content/plugins/demo/database.json', false],
    ['wp-content/themes/demo/private/data.txt', false],
    ['wp-content/plugins/demo/vendor/library.php', false],
    ['wp-content/plugins/demo/access.log', false],
    ['wp-content/plugins/demo/secret-key.txt', false],
];
foreach ($allowed as [$path, $dir]) {
    if (!SourcePolicy::allows($path, $dir)) {
        throw new RuntimeException('Expected allowed: ' . $path);
    }
}
foreach ($blocked as [$path, $dir]) {
    if (SourcePolicy::allows($path, $dir)) {
        throw new RuntimeException('Expected denied: ' . $path);
    }
}
echo "SourcePolicy tests passed\n";
