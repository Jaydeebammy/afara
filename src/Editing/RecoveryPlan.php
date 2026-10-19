<?php
declare(strict_types=1);

namespace Afara\Editing;

/**
 * Pure recovery decision logic. Does not open, write, or execute any files.
 * A persistent journal and durable storage are required before deployment.
 */
final class RecoveryPlan
{
    public const PREPARED = 'prepared';
    public const COMMITTED = 'committed';
    public const CONFLICT = 'conflict';

    /**
     * Decide whether a recovery operation is safe based on immutable hashes.
     * The caller must recheck all hashes and permissions under an exclusive lock.
     */
    public static function decide(string $beforeSha, string $afterSha, string $currentSha, bool $backupVerified): string
    {
        foreach ([$beforeSha, $afterSha, $currentSha] as $sha) {
            if (!preg_match('/\A[a-f0-9]{64}\z/D', $sha)) {
                throw new \InvalidArgumentException('Invalid content hash');
            }
        }
        if (!$backupVerified) {
            return self::CONFLICT;
        }
        if (hash_equals($currentSha, $beforeSha)) {
            return self::PREPARED;
        }
        if (hash_equals($currentSha, $afterSha)) {
            return self::COMMITTED;
        }
        return self::CONFLICT;
    }
}
