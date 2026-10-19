<?php
declare(strict_types=1);

namespace Afara\Audit;

/** Audit an ability result without retaining its arguments or response. */
final class AuditCallback
{
    public static function wrap(callable $callback, string $ability): callable
    {
        return static function (...$args) use ($callback, $ability) {
            try {
                $result = $callback(...$args);
                $failed = is_wp_error($result);
                ActivityLog::record($ability, !$failed, $failed ? (string) $result->get_error_code() : '');
                return $result;
            } catch (\Throwable $error) {
                ActivityLog::record($ability, false, 'afara_unexpected_error');
                throw $error;
            }
        };
    }
}
