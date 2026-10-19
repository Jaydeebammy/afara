<?php
declare(strict_types=1);

$GLOBALS['afara_sandbox_options'] = [];
function get_option(string $name, $default = false) { return $GLOBALS['afara_sandbox_options'][$name] ?? $default; }
function update_option(string $name, $value, $autoload = null): bool { $GLOBALS['afara_sandbox_options'][$name] = $value; return true; }
require dirname(__DIR__) . '/src/Sandbox/SandboxState.php';

use Afara\Sandbox\SandboxState;

if (!SandboxState::isSafeMode()) {
    throw new RuntimeException('Safe mode must default to on');
}
SandboxState::leaveSafeMode();
if (SandboxState::isSafeMode()) {
    throw new RuntimeException('Leaving safe mode failed');
}
SandboxState::enterSafeMode();
if (!SandboxState::isSafeMode()) {
    throw new RuntimeException('Reentering safe mode failed');
}
echo "SandboxState tests passed\n";
