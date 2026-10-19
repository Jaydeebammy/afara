<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/Security/PathGuard.php';
require dirname(__DIR__) . '/src/Security/SourcePolicy.php';
require dirname(__DIR__) . '/src/Security/ReadablePaths.php';

use Afara\Security\PathGuard;
use Afara\Security\ReadablePaths;

$root = sys_get_temp_dir() . '/afara-reads-' . bin2hex(random_bytes(6));
mkdir($root);
mkdir($root . '/wp-content');
mkdir($root . '/wp-content/themes');
mkdir($root . '/wp-content/themes/demo');
mkdir($root . '/wp-content/uploads');
file_put_contents($root . '/wp-content/themes/demo/style.css', 'body{}');
file_put_contents($root . '/wp-content/themes/demo/.env', 'secret');
file_put_contents($root . '/wp-content/themes/demo/config.php', 'secret');
file_put_contents($root . '/wp-content/uploads/private.txt', 'secret');
$guard = new ReadablePaths(new PathGuard($root));
try {
    if ($guard->resolve('wp-content/themes/demo/style.css') === null) throw new RuntimeException('source file denied');
    if ($guard->resolve('wp-content/themes/demo', true) === null) throw new RuntimeException('source directory denied');
    foreach (['wp-content/uploads/private.txt', 'wp-content/themes/demo/.env', 'wp-content/themes/demo/config.php', 'wp-content/themes/demo/../demo/style.css', 'wp-config.php'] as $path) {
        if ($guard->resolve($path) !== null) throw new RuntimeException('unsafe path allowed: ' . $path);
    }
    echo "ReadablePaths tests passed\n";
} finally {
    unlink($root . '/wp-content/themes/demo/style.css');
    unlink($root . '/wp-content/themes/demo/.env');
    unlink($root . '/wp-content/themes/demo/config.php');
    unlink($root . '/wp-content/uploads/private.txt');
    rmdir($root . '/wp-content/themes/demo');
    rmdir($root . '/wp-content/themes');
    rmdir($root . '/wp-content/uploads');
    rmdir($root . '/wp-content');
    rmdir($root);
}
