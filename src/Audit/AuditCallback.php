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
                ActivityLog::record($ability, !is_wp_error($result));
                return $result;
            } catch (\Throwable $error) {
                ActivityLog::record($ability, false);
                throw $error;
            }
        };
    }
}
