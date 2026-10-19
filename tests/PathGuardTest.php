<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Security/PathGuard.php';

use Afara\Security\PathGuard;

$root = sys_get_temp_dir() . '/afara-guard-' . bin2hex(random_bytes(6));
mkdir($root);
mkdir($root . '/safe');
file_put_contents($root . '/safe/hello.txt', 'hello');
$guard = new PathGuard($root);
$assert = static function (bool $condition, string $message): void {
    if (!$condition) { throw new RuntimeException($message); }
};
try {
    $assert($guard->resolveForRead('safe/hello.txt') === realpath($root . '/safe/hello.txt'), 'valid path');
    $assert($guard->resolveForRead('../etc/passwd') === null, 'parent traversal');
    $assert($guard->resolveForRead('/etc/passwd') === null, 'absolute path');
    $assert($guard->resolveForRead('safe/../safe/hello.txt') === null, 'embedded traversal');
    $assert($guard->resolveForRead('missing.txt') === null, 'missing path');
    $outside = tempnam(sys_get_temp_dir(), 'afara-external-');
    if (function_exists('symlink') && symlink($outside, $root . '/safe/link')) {
        $assert($guard->resolveForRead('safe/link') === null, 'symlink');
        unlink($root . '/safe/link');
    }
    unlink($outside);
    echo "PathGuard tests passed\n";
} finally {
    unlink($root . '/safe/hello.txt');
    rmdir($root . '/safe');
    rmdir($root);
}
