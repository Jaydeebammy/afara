<?php
declare(strict_types=1);

namespace Afara\Security;

/**
 * Denies sensitive source names even inside otherwise readable directories.
 * This is defence in depth, not a secret scanner.
 */
final class SourcePolicy
{
    public static function allows(string $path, bool $directory = false): bool
    {
        $parts = explode('/', strtolower($path));
        foreach ($parts as $part) {
            if ($part === '' || str_starts_with($part, '.')
                || in_array($part, [
                    'vendor', 'node_modules', 'cache', 'backups', 'backup',
                    'private', 'secrets', 'secret', 'credentials', 'credential',
                    'keys', 'key', 'logs',
                ], true)) {
                return false;
            }
        }

        if ($directory) {
            return true;
        }
        $name = end($parts);
        if (preg_match('/(^|[._-])(config|secret|credentials?|passwords?|private|backup|dump|database|db)([._-]|$)/i', $name)) {
            return false;
        }
        return (bool) preg_match('/\.(php|css|js|json|md|txt|html|twig)$/i', $name);
    }
}
