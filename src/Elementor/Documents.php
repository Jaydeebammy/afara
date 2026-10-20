<?php
declare(strict_types=1);

namespace Afara\Elementor;

use Afara\Security\PermissionGate;
use Afara\Sandbox\SandboxState;
use Afara\OAuth\Http;

/** Narrow adapter for classic Elementor documents. No raw post-meta writes to live documents. */
final class Documents
{
    public const MAX_BYTES = 1048576;

    public function __construct(private readonly PermissionGate $gate) {}

    public function allowed(int $id, bool $write): bool
    {
        if (!$this->gate->canRead() || !is_user_logged_in() || !is_ssl() || !current_user_can('edit_post', $id)) {
            return false;
        }
        $post = get_post($id);
        if (!$post || !in_array($post->post_type, ['post', 'page'], true) || $post->post_status === 'trash') {
            return false;
        }
        return !$write || ($this->gate->canWrite() && !SandboxState::isSafeMode()
            && !Http::isBearerAuthenticated()
            && in_array(wp_get_environment_type(), ['local', 'development', 'staging'], true)
            && $post->post_status === 'draft');
    }

    /** @return array|\WP_Error */
    public function read(int $id)
    {
        if (!$this->allowed($id, false)) {
            return $this->error('afara_elementor_denied', 'Document access is not permitted.');
        }
        $document = $this->document($id);
        if (is_wp_error($document)) {
            return $document;
        }
        $elements = $this->elements($document);
        if (is_wp_error($elements)) {
            return $elements;
        }
        return ['post_id' => $id, 'sha256' => $this->checksum($id), 'elements' => $elements];
    }

    /** @return array|\WP_Error */
    public function update(int $id, string $elementId, string $expected, string $operation, $value)
    {
        if (!$this->allowed($id, true)) {
            return $this->error('afara_elementor_write_denied', 'Draft editing requires HTTPS, write mode, safe mode off and a staging/development site. OAuth grants remain read-only.');
        }
        if (!preg_match('/\A[a-f0-9]{64}\z/D', $expected) || !preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/D', $elementId)) {
            return $this->error('afara_elementor_input', 'A valid document checksum and element ID are required.');
        }
        $lock = 'afara_elementor_lock_' . $id;
        $token = wp_generate_uuid4();
        if (!add_option($lock, $token, '', false)) {
            return $this->error('afara_elementor_busy', 'An Afara edit is already in progress.');
        }
        $saving = false;
        $revision = 0;
        try {
            if (!function_exists('wp_check_post_lock')) {
                require_once ABSPATH . 'wp-admin/includes/post.php';
            }
            if ($this->editorLocked($id)) {
                return $this->error('afara_elementor_editor_lock', 'Close the WordPress/Elementor editor before an agent edit.');
            }
            $document = $this->document($id);
            if (is_wp_error($document)) { return $document; }
            $before = $this->elements($document);
            if (is_wp_error($before)) { return $before; }
            if (!hash_equals($expected, $this->checksum($id))) {
                return $this->error('afara_elementor_stale', 'Document changed. Read it again before editing.');
            }
            $next = $before;
            $matches = 0;
            $failure = null;
            $walk = function (array &$nodes, int $depth = 0) use (&$walk, &$matches, &$failure, $elementId, $operation, $value): void {
                if ($depth > 64) { $failure = $this->error('afara_elementor_structure', 'Document nesting exceeds the supported limit.'); return; }
                foreach ($nodes as &$node) {
                    if (!is_array($node)) { $failure = $this->error('afara_elementor_structure', 'Unsupported element structure.'); return; }
                    if (($node['id'] ?? '') === $elementId) {
                        ++$matches;
                        $result = $this->change($node, $operation, $value);
                        if (is_wp_error($result)) { $failure = $result; }
                    }
                    if (isset($node['elements']) && is_array($node['elements'])) { $walk($node['elements'], $depth + 1); }
                }
                unset($node);
            };
            $walk($next);
            if ($failure) { return $failure; }
            if ($matches !== 1) { return $this->error('afara_elementor_target', 'Exactly one existing widget must match the element ID.'); }
            if ($next === $before) { return $this->error('afara_elementor_no_change', 'The proposed edit does not change this widget.'); }
            $encoded = wp_json_encode($next);
            if (!is_string($encoded) || strlen($encoded) > self::MAX_BYTES) {
                return $this->error('afara_elementor_size', 'The updated document exceeds the supported size.');
            }
            if (!wp_revisions_enabled(get_post($id))) {
                return $this->error('afara_elementor_backup', 'Enable WordPress revisions for this post type before editing.');
            }
            // Force a snapshot even if only Elementor metadata differs from the last revision.
            $force = static fn (): bool => false;
            add_filter('wp_save_post_revision_check_for_changes', $force);
            try { $revision = wp_save_post_revision($id); }
            finally { remove_filter('wp_save_post_revision_check_for_changes', $force); }
            if (is_wp_error($revision) || !$revision || (int) get_post($revision)->post_parent !== $id) {
                return $this->error('afara_elementor_backup', 'Unable to create a revision backup.');
            }
            $raw = (string) get_post_meta($id, '_elementor_data', true);
            // update_post_meta redirects revision IDs to their parent; use metadata API for the backup only.
            update_metadata('post', $revision, '_elementor_data', wp_slash($raw));
            if (get_metadata('post', $revision, '_elementor_data', true) !== $raw) {
                return $this->error('afara_elementor_backup', 'Unable to verify the revision backup.');
            }
            if (!$this->allowed($id, true) || !hash_equals($expected, $this->checksum($id)) || $this->editorLocked($id)) {
                return $this->error('afara_elementor_stale', 'Permissions, lock or document changed before saving.');
            }
            $saving = true;
            if (!$document->save(['elements' => $next])) {
                throw new \RuntimeException('Elementor save failed');
            }
            $fresh = $this->document($id);
            if (is_wp_error($fresh) || $this->elements($fresh) != $next || get_post_status($id) !== 'draft') {
                throw new \RuntimeException('Elementor save verification failed');
            }
            return ['post_id' => $id, 'element_id' => $elementId, 'sha256' => $this->checksum($id), 'revision_id' => (int) $revision];
        } catch (\Throwable $error) {
            if ($saving) { SandboxState::enterSafeMode(); }
            return new \WP_Error('afara_elementor_save_failed', 'Edit failed. Inspect the revision backup before retrying; safe mode is enabled after a save failure.', ['revision_id' => (int) $revision]);
        } finally {
            if (get_option($lock) === $token) { delete_option($lock); }
        }
    }

    /** Respect active locks even when the browser editor belongs to this administrator. */
    private function editorLocked(int $id): bool
    {
        if (wp_check_post_lock($id)) { return true; }
        $lock = get_post_meta($id, '_edit_lock', true);
        if (!is_string($lock) || !preg_match('/\A([0-9]+):([0-9]+)\z/D', $lock, $parts)) { return false; }
        $window = function_exists('apply_filters') ? (int) apply_filters('wp_check_post_lock_window', 150) : 150;
        return (int) $parts[2] > 0 && (int) $parts[1] > time() - max(1, $window);
    }

    private function document(int $id)
    {
        if (!class_exists('Elementor\\Plugin') || !defined('ELEMENTOR_VERSION') || version_compare(ELEMENTOR_VERSION, '3.0.0', '<')) {
            return $this->error('afara_elementor_missing', 'Install and activate Elementor first.');
        }
        $document = \Elementor\Plugin::$instance->documents->get($id, false);
        if (!$document || !$document->is_built_with_elementor() || !$document->is_editable_by_current_user()
            || (int) $document->get_main_id() !== $id) {
            return $this->error('afara_elementor_document', 'An editable Elementor post or page is required.');
        }
        return $document;
    }

    private function elements($document)
    {
        $elements = $document->get_elements_data();
        $json = wp_json_encode($elements);
        if (!is_array($elements) || !is_string($json) || strlen($json) > self::MAX_BYTES) {
            return $this->error('afara_elementor_size', 'Document exceeds the supported size or format.');
        }
        return $elements;
    }

    private function checksum(int $id): string
    {
        return hash('sha256', (string) wp_json_encode([
            get_post_meta($id, '_elementor_data', true), get_post_meta($id, '_elementor_page_settings', true), get_post_status($id),
        ]));
    }

    private function change(array &$node, string $operation, $value)
    {
        if (($node['elType'] ?? '') !== 'widget' || !isset($node['settings']) || !is_array($node['settings'])) {
            return $this->error('afara_elementor_widget', 'Only existing classic Elementor widgets can be edited.');
        }
        $type = $node['widgetType'] ?? '';
        $fields = ['heading' => 'title', 'text-editor' => 'editor', 'button' => 'text'];
        $field = $operation === 'text' ? ($fields[$type] ?? null) : ($operation === 'image' && $type === 'image' ? 'image' : null);
        if ($field === null || !empty($node['settings']['__dynamic__'][$field])) {
            return $this->error('afara_elementor_widget', 'Unsupported widget or dynamic field.');
        }
        if ($operation === 'text') {
            if (!is_string($value) || strlen($value) > 16384 || !preg_match('//u', $value) || strpbrk($value, '[]') !== false) {
                return $this->error('afara_elementor_text', 'Use at most 16384 bytes of UTF-8 plain text without shortcodes.');
            }
            $text = sanitize_textarea_field($value);
            // Encode markup even for administrators with unfiltered_html.
            $node['settings'][$field] = $type === 'text-editor' ? '<p>' . nl2br(esc_html($text)) . '</p>' : esc_html($text);
        } else {
            if (!is_int($value) || $value < 1 || !current_user_can('read_post', $value) || !wp_attachment_is_image($value)
                || !in_array(get_post_mime_type($value), ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif'], true)) {
                return $this->error('afara_elementor_image', 'Choose an accessible raster image from the WordPress media library.');
            }
            $url = wp_get_attachment_url($value);
            if (!is_string($url) || esc_url_raw($url, ['https']) !== $url) {
                return $this->error('afara_elementor_image', 'The attachment requires a valid HTTPS URL.');
            }
            $node['settings']['image'] = ['id' => $value, 'url' => $url];
        }
        return true;
    }

    private function error(string $code, string $message): \WP_Error
    {
        return new \WP_Error($code, $message);
    }
}
