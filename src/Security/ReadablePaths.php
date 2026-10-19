<?php
declare(strict_types=1);

namespace Afara\Security;

/** A deliberately narrow read-only scope for the first file abilities. */
final class ReadablePaths
{
    public function __construct(private readonly PathGuard $guard) {}

    public function resolve(string $path, bool $directory = false): ?string
    {
        // Do not read configuration files, uploads, caches, or arbitrary installation files.
        $parts = explode('/', $path);
        if (count($parts) < 3 || $parts[0] !== 'wp-content'
            || !in_array($parts[1], ['themes', 'plugins'], true)) {
            return null;
        }
        foreach ($parts as $part) {
            if ($part === '' || $part[0] === '.' || in_array(strtolower($part), [
                'vendor', 'node_modules', 'cache', 'backups', 'backup', 'private',
            ], true)) {
                return null;
            }
        }
        $resolved = $this->guard->resolveForRead($path);
        if ($resolved === null || !is_readable($resolved)) {
            return null;
        }
        if ($directory) {
            return is_dir($resolved) ? $resolved : null;
        }
        if (!is_file($resolved) || !preg_match('/\.(php|css|js|json|md|txt|html|twig)$/i', $path)) {
            return null;
        }
        return $resolved;
    }
}
