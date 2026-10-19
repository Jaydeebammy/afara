<?php
declare(strict_types=1);

namespace Afara\Editing;

/**
 * Local-only editing primitive. Not registered in WordPress or MCP.
 *
 * Operates on one existing regular file within a caller-supplied disposable
 * directory. Callers must separately enforce permissions and environment.
 */
final class LocalAtomicWriter
{
    public function __construct(private readonly string $root, private readonly string $backupRoot)
    {
        $edit = realpath($root);
        $backups = realpath($backupRoot);
        if (!is_dir($root) || is_link($root) || $edit === false
            || !is_dir($backupRoot) || is_link($backupRoot) || $backups === false
            || $edit === $backups || str_starts_with($backups . '/', $edit . '/')
            || str_starts_with($edit . '/', $backups . '/')
            || !is_writable($backups)) {
            throw new \InvalidArgumentException('Edit and backup roots must be separate, writable directories');
        }
    }

    /** @return array{before_sha256:string,after_sha256:string,backup:string} */
    public function replace(string $name, string $expectedSha, string $updated): array
    {
        if (!preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}\.txt\z/D', $name)
            || str_contains($name, '..') || str_starts_with($name, '.')) {
            throw new \InvalidArgumentException('Only simple .txt filenames are supported');
        }
        if (strlen($updated) > EditPlanner::MAX_BYTES || !preg_match('//u', $updated)) {
            throw new \InvalidArgumentException('Invalid replacement content');
        }
        if (!preg_match('/\A[a-f0-9]{64}\z/D', $expectedSha)) {
            throw new \InvalidArgumentException('Invalid expected checksum');
        }
        $root = realpath($this->root);
        $backupRoot = realpath($this->backupRoot);
        if ($root === false || $backupRoot === false || is_link($this->backupRoot)
            || !is_writable($backupRoot) || $root === $backupRoot
            || str_starts_with($backupRoot . '/', $root . '/') || str_starts_with($root . '/', $backupRoot . '/')
            || is_link($this->root)) {
            throw new \RuntimeException('Root changed');
        }
        $path = $root . DIRECTORY_SEPARATOR . $name;
        if (is_link($path) || !is_file($path) || !is_readable($path) || !is_writable($path)) {
            throw new \RuntimeException('Target is not an editable regular file');
        }

        $lockPath = $root . '/.afara-edit.lock';
        if (is_link($lockPath) || (file_exists($lockPath) && !is_file($lockPath))) {
            throw new \RuntimeException('Unsafe lock file');
        }
        $lock = fopen($lockPath, 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new \RuntimeException('Unable to lock edit workspace');
        }
        $temp = null;
        $backup = null;
        $committed = false;
        try {
            clearstatcache(true, $path);
            if (is_link($path) || !is_file($path)) {
                throw new \RuntimeException('Target changed');
            }
            $source = file_get_contents($path);
            if ($source === false || strlen($source) > EditPlanner::MAX_BYTES) {
                throw new \RuntimeException('Cannot read target');
            }
            $actual = hash('sha256', $source);
            if (!hash_equals($expectedSha, $actual)) {
                throw new \RuntimeException('Stale source checksum');
            }
            if ($source === $updated) {
                throw new \InvalidArgumentException('No content change');
            }
            $backup = tempnam($backupRoot, '.afara-backup-');
            if ($backup === false || file_put_contents($backup, $source, LOCK_EX) !== strlen($source)) {
                throw new \RuntimeException('Cannot create backup');
            }
            chmod($backup, 0600);
            $temp = tempnam($root, '.afara-next-');
            if ($temp === false || file_put_contents($temp, $updated, LOCK_EX) !== strlen($updated)) {
                throw new \RuntimeException('Cannot stage replacement');
            }
            $mode = fileperms($path) & 0777;
            chmod($temp, $mode);
            // Best-effort symlink check; production use requires stronger OS-level
            // isolation against actors concurrently mutating the directory.
            if (is_link($path) || !hash_equals($actual, hash_file('sha256', $path))) {
                throw new \RuntimeException('Target changed during staging');
            }
            if (!rename($temp, $path)) {
                throw new \RuntimeException('Atomic replacement failed');
            }
            $temp = null;
            $committed = true;
            return ['before_sha256' => $actual, 'after_sha256' => hash('sha256', $updated), 'backup' => $backup];
        } finally {
            if (!$committed && is_string($backup) && is_file($backup)) {
                unlink($backup);
            }
            if (is_string($temp) && is_file($temp)) {
                unlink($temp);
            }
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function restore(string $name, string $backup, string $expectedCurrentSha): void
    {
        $backupRoot = realpath($this->backupRoot);
        if ($backupRoot === false || is_link($this->backupRoot) || dirname($backup) !== $backupRoot
            || !preg_match('/\A\.afara-backup-[a-zA-Z0-9]+\z/D', basename($backup))
            || is_link($backup) || !is_file($backup)) {
            throw new \InvalidArgumentException('Invalid backup');
        }
        $content = file_get_contents($backup);
        if ($content === false) {
            throw new \RuntimeException('Backup unreadable');
        }
        $this->replace($name, $expectedCurrentSha, $content);
    }
}
