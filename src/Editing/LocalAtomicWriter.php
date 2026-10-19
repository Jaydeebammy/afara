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
    public function __construct(private readonly string $root)
    {
        if (!is_dir($root) || is_link($root) || realpath($root) === false) {
            throw new \InvalidArgumentException('Invalid edit root');
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
        if ($root === false || is_link($this->root)) {
            throw new \RuntimeException('Root changed');
        }
        $path = $root . DIRECTORY_SEPARATOR . $name;
        if (is_link($path) || !is_file($path) || !is_readable($path) || !is_writable($path)) {
            throw new \RuntimeException('Target is not an editable regular file');
        }

        $lock = fopen($root . '/.afara-edit.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new \RuntimeException('Unable to lock edit workspace');
        }
        $temp = null;
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
            $backup = tempnam($root, '.afara-backup-');
            if ($backup === false || file_put_contents($backup, $source, LOCK_EX) !== strlen($source)) {
                throw new \RuntimeException('Cannot create backup');
            }
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
            return ['before_sha256' => $actual, 'after_sha256' => hash('sha256', $updated), 'backup' => $backup];
        } finally {
            if (is_string($temp) && is_file($temp)) {
                unlink($temp);
            }
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function restore(string $name, string $backup, string $expectedCurrentSha): void
    {
        $root = realpath($this->root);
        if ($root === false || !str_starts_with($backup, $root . '/.afara-backup-') || is_link($backup) || !is_file($backup)) {
            throw new \InvalidArgumentException('Invalid backup');
        }
        $content = file_get_contents($backup);
        if ($content === false) {
            throw new \RuntimeException('Backup unreadable');
        }
        $this->replace($name, $expectedCurrentSha, $content);
    }
}
