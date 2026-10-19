<?php
declare(strict_types=1);

$GLOBALS['afara_audit_options'] = [];
function get_option(string $name, $default = false) { return $GLOBALS['afara_audit_options'][$name] ?? $default; }
function update_option(string $name, $value, $autoload = null): bool {
    $GLOBALS['afara_audit_options'][$name] = $value;
    return true;
}
function get_current_user_id(): int { return 17; }

require dirname(__DIR__) . '/src/Audit/ActivityLog.php';

use Afara\Audit\ActivityLog;

ActivityLog::record('afara/read-file', true);
ActivityLog::record('afara/unknown', true);
$items = ActivityLog::recent();
if (count($items) !== 1 || $items[0]['ability'] !== 'afara/read-file' || $items[0]['user_id'] !== 17) {
    throw new RuntimeException('Failed to create a sanitized audit entry.');
}
for ($i = 0; $i < 210; $i++) {
    ActivityLog::record('afara/site-context', false);
}
$items = ActivityLog::recent();
if (count($items) !== ActivityLog::LIMIT || $items[0]['result'] !== 'error') {
    throw new RuntimeException('Audit retention limit failed.');
}
foreach ($items as $entry) {
    if (array_diff(array_keys($entry), ['time', 'user_id', 'ability', 'result'])) {
        throw new RuntimeException('Audit entry contains unexpected fields.');
    }
}
echo "ActivityLog tests passed\n";
