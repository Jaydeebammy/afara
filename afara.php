<?php
/**
 * Plugin Name: Afara
 * Description: A permission-gated bridge between AI agents and WordPress.
 * Version: 0.1.0
 * Requires at least: 6.9
 * Requires PHP: 8.1
 * License: GPL-2.0-or-later
 * Text Domain: afara
 */
declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}
define('AFARA_VERSION', '0.1.0');
define('AFARA_PLUGIN_FILE', __FILE__);

spl_autoload_register(static function (string $class): void {
    $prefix = 'Afara\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require_once $path;
    }
});

add_action('plugins_loaded', static function (): void {
    (new \Afara\Plugin())->boot();
});
