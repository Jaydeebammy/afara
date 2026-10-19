<?php
declare(strict_types=1);

$GLOBALS['afara_audit_options'] = [];
$GLOBALS['afara_audit_user'] = 17;
function get_option(string $name, $default = false) { return $GLOBALS['afara_audit_options'][$name] ?? $default; }
function update_option(string $name, $value, $autoload = null): bool {
    $GLOBALS['afara_audit_options'][$name] = $value;
    return true;
}
function get_current_user_id(): int { return $GLOBALS['afara_audit_user']; }
function get_userdata(int $id) { return $id === 17 ? (object) ['user_login' => 'jaydee'] : false; }
function check(bool $ok, string $label): void { if (!$ok) { throw new RuntimeException($label); } }

require dirname(__DIR__) . '/src/Audit/ActivityLog.php';

use Afara\Audit\ActivityLog;

$reset = static function (): void { $GLOBALS['afara_audit_options'] = []; ActivityLog::resetConnection(); };

// Successful execution: who, which connection, which ability.
ActivityLog::useConnection("Claude Desktop\x07", 'uuid-1');
ActivityLog::record('afara/read-file', true);
ActivityLog::record('afara/unknown', true);
$items = ActivityLog::recent();
check(count($items) === 1, 'unknown abilities are not logged');
check($items[0]['ability'] === 'afara/read-file' && $items[0]['result'] === 'success', 'success recorded');
check($items[0]['user_id'] === 17 && $items[0]['user_login'] === 'jaydee', 'records user ID and login');
check($items[0]['connection'] === 'Claude Desktop', 'records connection label with control characters removed');
check($items[0]['reason'] === '', 'success has no reason');

// Errors keep the code only; free text is never stored.
ActivityLog::record('afara/read-file', false, 'afara_path_denied');
ActivityLog::record('afara/read-file', false, 'Path /etc/passwd is not permitted');
$items = ActivityLog::recent();
check($items[1]['reason'] === 'afara_path_denied', 'error reason code stored');
check($items[0]['reason'] === 'unknown', 'free-text reason replaced with "unknown"');
check(!str_contains(json_encode(get_option(ActivityLog::OPTION)), 'passwd'), 'no path text stored');

// Refusals: transport-level, anonymous, collapsed when repeated.
$reset();
$GLOBALS['afara_audit_user'] = 0;
for ($i = 0; $i < 500; $i++) {
    ActivityLog::refused('incorrect_password');
}
$items = ActivityLog::recent();
check(count($items) === 1 && $items[0]['count'] === 500, 'burst of identical refusals collapses to one counted row');
check($items[0]['result'] === 'refused' && $items[0]['ability'] === '' && $items[0]['user_login'] === '', 'anonymous transport refusal');
ActivityLog::refused('afara_not_signed_in');
check(count(ActivityLog::recent()) === 2, 'different reason starts a new row');
ActivityLog::refused('afara_not_signed_in', 'afara/evil');
check(count(ActivityLog::recent()) === 2, 'refusal for unknown ability ignored');

// A refusal older than the collapse window starts a new row.
$stored = get_option(ActivityLog::OPTION);
$stored[array_key_last($stored)]['time'] = gmdate('Y-m-d\TH:i:s\Z', time() - ActivityLog::COLLAPSE_SECONDS - 5);
update_option(ActivityLog::OPTION, $stored);
ActivityLog::refused('afara_not_signed_in');
check(count(ActivityLog::recent()) === 3, 'stale refusal not merged');

// Real activity in between breaks a collapse run, so ordering stays truthful.
$GLOBALS['afara_audit_user'] = 17;
ActivityLog::record('afara/site-context', true);
ActivityLog::refused('afara_not_signed_in');
check(count(ActivityLog::recent()) === 5, 'success between refusals keeps them separate');

// Counting for the summary panel.
check(ActivityLog::refusedSince(86400) === 500 + 1 + 1 + 1, 'refusedSince sums collapsed counts');
check(ActivityLog::refusedSince(60, time() + 3600) === 0, 'refusedSince respects the window');

// Retention limit and exact field set.
$reset();
for ($i = 0; $i < 210; $i++) {
    ActivityLog::record('afara/site-context', false, 'afara_read_failed');
}
$items = ActivityLog::recent();
check(count($items) === ActivityLog::LIMIT && $items[0]['result'] === 'error', 'retention limit');
foreach (get_option(ActivityLog::OPTION) as $entry) {
    check(array_keys($entry) === ActivityLog::FIELDS, 'stored entry has exactly the documented fields');
}

// Entries written by the previous version still display.
update_option(ActivityLog::OPTION, [['time' => '2026-10-01T10:00:00Z', 'user_id' => 1, 'ability' => 'afara/read-file', 'result' => 'success']]);
$items = ActivityLog::recent();
check($items[0]['count'] === 1 && $items[0]['connection'] === '' && $items[0]['reason'] === '', 'legacy entry normalised');

echo "ActivityLog tests passed\n";
