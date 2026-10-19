<?php
declare(strict_types=1);

namespace Afara\Editing;

/**
 * Pure, side-effect-free editing preflight. No filesystem writes or execution.
 * An eventual editor must recheck permissions and source hashes at commit time.
 */
final class EditPlanner
{
    public const MAX_BYTES = 1048576;

    /** @return array{before_sha256:string,after_sha256:string,replacements:int,preview:string,bytes:int} */
    public static function plan(string $source, string $old, string $new, bool $replaceAll = false): array
    {
        if ($old === '') {
            throw new \InvalidArgumentException('Search text cannot be empty.');
        }
        if (strlen($source) > self::MAX_BYTES || strlen($old) > self::MAX_BYTES || strlen($new) > self::MAX_BYTES) {
            throw new \InvalidArgumentException('Input exceeds the byte limit.');
        }
        if (!preg_match('//u', $source) || !preg_match('//u', $old) || !preg_match('//u', $new)) {
            throw new \InvalidArgumentException('Only UTF-8 text is supported.');
        }
        $count = substr_count($source, $old);
        if ($count === 0) {
            throw new \InvalidArgumentException('Search text was not found.');
        }
        if (!$replaceAll && $count !== 1) {
            throw new \InvalidArgumentException('Search text must match exactly once.');
        }
        $updated = $replaceAll ? str_replace($old, $new, $source) : substr_replace($source, $new, strpos($source, $old), strlen($old));
        if (strlen($updated) > self::MAX_BYTES) {
            throw new \InvalidArgumentException('Result exceeds the byte limit.');
        }
        return [
            'before_sha256' => hash('sha256', $source),
            'after_sha256' => hash('sha256', $updated),
            'replacements' => $replaceAll ? $count : 1,
            'preview' => $updated,
            'bytes' => strlen($updated),
        ];
    }
}
