<?php
declare(strict_types=1);

namespace Afara\Sandbox;

/**
 * Fail-closed sandbox state. This milestone does NOT load or execute agent PHP.
 * Crash recovery must be implemented and tested separately before enabling code.
 */
final class SandboxState
{
    public const OPTION = 'afara_sandbox_safe_mode';

    public static function isSafeMode(): bool
    {
        return get_option(self::OPTION, '1') !== '0';
    }

    public static function enterSafeMode(): void
    {
        update_option(self::OPTION, '1', false);
    }

    public static function leaveSafeMode(): void
    {
        // Deliberately no executor is enabled by leaving safe mode.
        update_option(self::OPTION, '0', false);
    }

    public static function path(): string
    {
        return WP_CONTENT_DIR . '/afara-sandbox';
    }

    /**
     * Prepare an inert directory. Deny direct PHP execution at the server
     * configuration level as a backup only; webserver-specific restrictions
     * must be verified in deployment.
     */
    public static function prepare(): bool
    {
        $path = self::path();
        if (is_link($path)) {
            return false;
        }
        if (!is_dir($path) && !wp_mkdir_p($path)) {
            return false;
        }
        if (!is_dir($path) || !is_writable($path)) {
            return false;
        }
        $files = [
            'index.php' => "<?php\n// Silence is golden.\n",
            '.htaccess' => "Require all denied\nDeny from all\n",
            'web.config' => '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><security><authorization><deny users="*" /></authorization></security></system.webServer></configuration>',
        ];
        foreach ($files as $name => $content) {
            $target = $path . '/' . $name;
            if (is_link($target) || (file_exists($target) && !is_file($target))) {
                return false;
            }
            if (!file_exists($target) && file_put_contents($target, $content, LOCK_EX) === false) {
                return false;
            }
        }
        return true;
    }
}
