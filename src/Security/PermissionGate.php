<?php
declare(strict_types=1);

namespace Afara\Security;

final class PermissionGate
{
    public function isEnabled(): bool
    {
        return get_option('afara_enabled', '0') === '1';
    }

    public function isDomainMatched(): bool
    {
        $locked = (string) get_option('afara_domain_lock', '');
        $current = wp_parse_url(home_url(), PHP_URL_HOST);
        return $locked !== '' && is_string($current)
            && hash_equals(strtolower($locked), strtolower($current));
    }

    public function canRead(): bool
    {
        return $this->isEnabled()
            && $this->isDomainMatched()
            && current_user_can('manage_options');
    }

    /**
     * Why canRead() is false, as a short code for the Activity log, or null if allowed.
     * Checked in the same order the admin pages explain them.
     */
    public function readDenialReason(): ?string
    {
        if (!$this->isEnabled()) {
            return 'afara_disabled';
        }
        if (!$this->isDomainMatched()) {
            return 'afara_domain_mismatch';
        }
        if (!current_user_can('manage_options')) {
            return 'afara_not_admin';
        }
        return null;
    }

    public function canWrite(): bool
    {
        return $this->canRead()
            && get_option('afara_read_only', '1') === '0';
    }
}
