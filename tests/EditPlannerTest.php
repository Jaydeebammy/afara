<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/Editing/EditPlanner.php';

use Afara\Editing\EditPlanner;

function expectRejection(callable $operation, string $label): void
{
    try {
        $operation();
    } catch (InvalidArgumentException $error) {
        return;
    }
    throw new RuntimeException('Expected rejection: ' . $label);
}

$plan = EditPlanner::plan("hello world\n", 'world', 'Afara');
if ($plan['preview'] !== "hello Afara\n" || $plan['replacements'] !== 1) {
    throw new RuntimeException('Single exact match edit failed.');
}
if ($plan['before_sha256'] !== hash('sha256', "hello world\n")) {
    throw new RuntimeException('Original checksum incorrect.');
}
expectRejection(static fn () => EditPlanner::plan('aaa', 'a', 'b'), 'ambiguous match');
expectRejection(static fn () => EditPlanner::plan('abc', 'missing', 'x'), 'missing match');
expectRejection(static fn () => EditPlanner::plan('abc', '', 'x'), 'empty match');
expectRejection(static fn () => EditPlanner::plan('abc', 'a', str_repeat('x', EditPlanner::MAX_BYTES + 1)), 'oversized output');
$all = EditPlanner::plan('one one', 'one', 'two', true);
if ($all['preview'] !== 'two two' || $all['replacements'] !== 2) {
    throw new RuntimeException('Replace-all failed.');
}
echo "EditPlanner tests passed\n";
