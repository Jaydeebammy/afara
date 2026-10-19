<?php
declare(strict_types=1);

namespace Afara\Security;

/**
 * Resolves existing paths without following an entry outside the WordPress root.
 * This class provides read-only validation; it does not authorize writes.
 */
final class PathGuard
{
    private string $root;

    public function __construct(string $root)
    {
        $resolved = realpath($root);
        if ($resolved === false || !is_dir($resolved)) {
            throw new \InvalidArgumentException('Invalid WordPress root.');
        }
        $this->root = rtrim($resolved, DIRECTORY_SEPARATOR);
    }

    public function resolveForRead(string $relativePath): ?string
    {
        if ($relativePath === '' || str_contains($relativePath, "\0")
            || str_contains($relativePath, '\\') || str_starts_with($relativePath, '/')
            || preg_match('/^[A-Za-z]:/', $relativePath)) {
            return null;
        }
        foreach (explode('/', $relativePath) as $part) {
            if ($part === '..' || $part === '.' || $part === '') {
                return null;
            }
        }
        $candidate = $this->root . DIRECTORY_SEPARATOR . $relativePath;
        $resolved = realpath($candidate);
        if ($resolved === false || !str_starts_with($resolved, $this->root . DIRECTORY_SEPARATOR)) {
            return null;
        }
        // Reject symlinks in any path component rather than trusting realpath alone.
        $cursor = $this->root;
        foreach (explode('/', $relativePath) as $part) {
            $cursor .= DIRECTORY_SEPARATOR . $part;
            if (is_link($cursor)) {
                return null;
            }
        }
        return $resolved;
    }
}
