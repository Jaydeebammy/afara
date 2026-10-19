<?php
declare(strict_types=1);

require __DIR__ . '/SettingsPageTest.php';

$removed = [];
function remove_menu_page($slug): void { global $removed; $removed[] = $slug; }
function add_filter($name, $callback, $priority = 10, $args = 1): void { global $hooks; $hooks[$name][] = $callback; }
function plugin_basename($file): string { return 'afara/afara.php'; }
define('AFARA_PLUGIN_FILE', '/srv/wp-content/plugins/afara/afara.php');

use Afara\Admin\QuietMode;
use Afara\Admin\SettingsPage;

// Me (1) and a client admin (2); 9 used to be an admin and was deleted.
$wpUsers = [
    (object) ['ID' => 1, 'user_login' => 'jaydee', 'display_name' => 'Jaydee'],
    (object) ['ID' => 2, 'user_login' => 'client', 'display_name' => 'Client <Admin>'],
];
$admin = true; $_GET = [];
$quiet = new QuietMode();
$quiet->register();
check(isset($hooks['all_plugins'], $hooks['site_transient_update_plugins']), 'plugin and update filters registered');
$plugins = ['afara/afara.php' => ['Name' => 'Afara'], 'akismet/akismet.php' => ['Name' => 'Akismet']];
$updates = (object) ['response' => ['afara/afara.php' => 'x', 'akismet/akismet.php' => 'y'], 'no_update' => ['afara/afara.php' => 'z']];
$as = static function (int $id): void { global $userId; $userId = $id; };

// Off by default: everyone sees everything.
$options = [];
$as(2);
check(!QuietMode::isActive() && QuietMode::visibleToCurrentUser(), 'off by default');
check(isset($quiet->hidePluginRow($plugins)['afara/afara.php']), 'plugin row visible when off');

// Turning it on: the person saving is always added; non-admins are dropped.
$as(1);
$options[QuietMode::OPTION_ENABLED] = QuietMode::sanitizeEnabled('1');
$options[QuietMode::OPTION_USERS] = QuietMode::sanitizeUsers(['9', 'abc']);
check($options[QuietMode::OPTION_USERS] === [1], 'saver always included, non-admins and junk dropped');
check(QuietMode::isActive(), 'active with a listed administrator');

// Listed admin sees Afara.
$removed = [];
$quiet->hideMenu();
check($removed === [] && isset($quiet->hidePluginRow($plugins)['afara/afara.php']), 'listed admin sees menu and plugin row');
check(isset($quiet->hideUpdateRow($updates)->response['afara/afara.php']), 'listed admin sees update row');

// Unlisted admin doesn't.
$as(2);
$quiet->hideMenu();
check($removed === ['afara'], 'menu hidden from unlisted admin');
$visible = $quiet->hidePluginRow($plugins);
check(!isset($visible['afara/afara.php']) && isset($visible['akismet/akismet.php']), 'only Afara’s plugin row hidden');
$filtered = $quiet->hideUpdateRow($updates);
check(!isset($filtered->response['afara/afara.php']) && !isset($filtered->no_update['afara/afara.php']) && isset($filtered->response['akismet/akismet.php']), 'only Afara’s update rows hidden');
check(isset($updates->response['afara/afara.php']), 'stored update data untouched');
check(!QuietMode::visibleToCurrentUser(), 'single check for future notices');

// It hides, it doesn't block: the permission gate is unchanged.
$options['afara_enabled'] = '1'; $options['afara_domain_lock'] = 'staging.example.test';
check((new \Afara\Security\PermissionGate())->canRead(), 'hidden admin still passes the permission gate');

// A hidden admin can't turn it off or rewrite the list.
check(QuietMode::sanitizeEnabled('0') === '1' && QuietMode::sanitizeUsers(['2']) === [1], 'hidden admin cannot change quiet settings');

// Settings page shows status, list and the way back in.
$as(1);
$page = new SettingsPage();
ob_start(); $page->render(); $html = (string) ob_get_clean();
check(str_contains($html, 'Quiet mode on — hidden from 1 administrator') && str_contains($html, 'dashicons-hidden'), 'status names how many are hidden');
check(str_contains($html, 'You — always included') && str_contains($html, 'Client &lt;Admin&gt;'), 'list shows you locked on and escapes names');
check(str_contains($html, "define('AFARA_QUIET_MODE_OFF', true);") && str_contains($html, 'Quiet mode hides, it doesn’t block.'), 'way back in and honesty note shown');

// Fail-safe: if no listed account is an administrator any more, nothing is hidden.
$options[QuietMode::OPTION_USERS] = [9];
$as(2);
check(!QuietMode::isActive() && QuietMode::visibleToCurrentUser(), 'losing every listed admin unhides Afara');
$options[QuietMode::OPTION_USERS] = [1];

// wp-config way back in.
check(!QuietMode::visibleToCurrentUser(), 'hidden before constant');
define('AFARA_QUIET_MODE_OFF', true);
check(QuietMode::forcedOff() && !QuietMode::isActive() && QuietMode::visibleToCurrentUser(), 'constant shows Afara to everyone');
$as(1);
ob_start(); $page->render(); $html = (string) ob_get_clean();
check(str_contains($html, 'switched off by wp-config.php') && str_contains($html, 'value="1"><input type="checkbox" name="afara_quiet_mode" value="1"'), 'forced off keeps the saved setting on save');
echo "Quiet mode tests passed\n";
