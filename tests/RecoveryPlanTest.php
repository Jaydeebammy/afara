<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Editing/RecoveryPlan.php';

use Afara\Editing\RecoveryPlan;

$before = hash('sha256', 'before');
$after = hash('sha256', 'after');
$other = hash('sha256', 'unrelated');
if (RecoveryPlan::decide($before, $after, $before, true) !== RecoveryPlan::PREPARED) {
    throw new RuntimeException('Interrupted preparation should preserve original');
}
if (RecoveryPlan::decide($before, $after, $after, true) !== RecoveryPlan::COMMITTED) {
    throw new RuntimeException('Committed file should be recognized');
}
if (RecoveryPlan::decide($before, $after, $other, true) !== RecoveryPlan::CONFLICT) {
    throw new RuntimeException('Unrelated change must not be overwritten');
}
if (RecoveryPlan::decide($before, $after, $after, false) !== RecoveryPlan::CONFLICT) {
    throw new RuntimeException('Missing or corrupt backup must halt recovery');
}
try {
    RecoveryPlan::decide('invalid', $after, $after, true);
    throw new RuntimeException('Invalid hashes allowed');
} catch (InvalidArgumentException $e) {
}
echo "RecoveryPlan tests passed\n";
