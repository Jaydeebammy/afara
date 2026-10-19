<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Editing/EditPlanner.php';
require dirname(__DIR__) . '/src/Editing/LocalAtomicWriter.php';

use Afara\Editing\LocalAtomicWriter;

$root = sys_get_temp_dir() . '/afara-writer-' . bin2hex(random_bytes(6));
mkdir($root);
file_put_contents($root . '/note.txt', 'old');
$writer = new LocalAtomicWriter($root);
try {
    $first = $writer->replace('note.txt', hash('sha256', 'old'), 'new');
    if (file_get_contents($root . '/note.txt') !== 'new'
        || file_get_contents($first['backup']) !== 'old') {
        throw new RuntimeException('Atomic write or backup failed');
    }
    try {
        $writer->replace('note.txt', hash('sha256', 'old'), 'bad');
        throw new RuntimeException('Stale checksum accepted');
    } catch (RuntimeException $e) {
        if ($e->getMessage() === 'Stale checksum accepted') throw $e;
    }
    $writer->restore('note.txt', $first['backup'], hash('sha256', 'new'));
    if (file_get_contents($root . '/note.txt') !== 'old') {
        throw new RuntimeException('Rollback failed');
    }
    try {
        $writer->replace('../wp-config.php', hash('sha256', 'old'), 'bad');
        throw new RuntimeException('Traversal accepted');
    } catch (InvalidArgumentException $e) {
        if ($e->getMessage() === 'Traversal accepted') throw $e;
    }
    echo "LocalAtomicWriter tests passed\n";
} finally {
    foreach (glob($root . '/*') ?: [] as $f) { if (is_file($f)) unlink($f); }
    foreach (glob($root . '/.*') ?: [] as $f) { if (is_file($f)) unlink($f); }
    rmdir($root);
}
