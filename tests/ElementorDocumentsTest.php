<?php
declare(strict_types=1);
namespace Elementor {
    final class Plugin { public static $instance; }
}
namespace {
    define('ELEMENTOR_VERSION', '3.35.0');
    $options = ['afara_enabled' => '1', 'afara_domain_lock' => 'staging.test', 'afara_read_only' => '0', 'afara_sandbox_safe_mode' => '0'];
    $admin = true; $edit = true; $ssl = true; $environment = 'staging'; $oauth = false; $locked = false; $backupFails = false;
    $post = (object) ['ID' => 7, 'post_type' => 'page', 'post_status' => 'draft'];
    $tree = [['id' => 'root', 'elType' => 'container', 'settings' => [], 'elements' => [
        ['id' => 'heading1', 'elType' => 'widget', 'widgetType' => 'heading', 'settings' => ['title' => 'Before', 'align' => 'center'], 'elements' => []],
        ['id' => 'image1', 'elType' => 'widget', 'widgetType' => 'image', 'settings' => ['image' => ['id' => 1, 'url' => 'https://staging.test/old.png']], 'elements' => []],
    ]]];
    $meta = [7 => ['_elementor_data' => json_encode($tree), '_elementor_page_settings' => []]];
    $saves = 0; $saveFails = false; $postLock = false; $filters = [];
    class WP_Error {
        public function __construct(public $code, public $message = '', public $data = []) {}
        public function get_error_code() { return $this->code; }
    }
    function is_wp_error($v): bool { return $v instanceof WP_Error; }
    function get_option($k, $d = false) { global $options; return $options[$k] ?? $d; }
    function update_option($k, $v, $autoload = false) { global $options; $options[$k] = $v; return true; }
    function add_option($k, $v, $unused = '', $autoload = false): bool { global $options; if (isset($options[$k])) { return false; } $options[$k] = $v; return true; }
    function delete_option($k): void { global $options; unset($options[$k]); }
    function home_url(): string { return 'https://staging.test'; }
    function wp_parse_url($u, $c) { return parse_url($u, $c); }
    function is_ssl(): bool { global $ssl; return $ssl; }
    function is_user_logged_in(): bool { global $admin; return $admin; }
    function current_user_can($c, $id = 0): bool { global $admin, $edit; return $admin && ($c !== 'edit_post' || $edit); }
    function get_post($id) { global $post; return $id === 7 ? $post : ($id === 99 ? (object) ['post_parent' => 7] : null); }
    function get_post_status($id): string { global $post; return $post->post_status; }
    function wp_get_environment_type(): string { global $environment; return $environment; }
    function wp_generate_uuid4(): string { return 'test-lock-token'; }
    function wp_check_post_lock($id) { global $postLock; return $postLock ? 2 : false; }
    function wp_json_encode($v) { return json_encode($v); }
    function get_post_meta($id, $k, $single) { global $meta; return $meta[$id][$k] ?? ''; }
    function get_metadata($type, $id, $k, $single) { return get_post_meta($id, $k, $single); }
    function update_metadata($type, $id, $k, $v) { global $meta; $meta[$id][$k] = stripslashes($v); return true; }
    function wp_slash($v) { return addslashes($v); }
    function wp_revisions_enabled($p): bool { return true; }
    function add_filter($k, $cb): void { global $filters; $filters[$k] = $cb; }
    function remove_filter($k, $cb): void { global $filters; unset($filters[$k]); }
    function wp_save_post_revision($id) { global $backupFails; return $backupFails ? 0 : 99; }
    function sanitize_textarea_field($v): string { return strip_tags($v); }
    function esc_html($v): string { return htmlspecialchars($v, ENT_QUOTES); }
    function wp_attachment_is_image($id): bool { return $id === 42; }
    function get_post_mime_type($id): string { return 'image/png'; }
    function wp_get_attachment_url($id): string { return 'https://staging.test/new.png'; }
    function esc_url_raw($u, $schemes): string { return $u; }
    spl_autoload_register(static function ($class): void {
        if (str_starts_with($class, 'Afara\\')) { require_once dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, 6)) . '.php'; }
    });
    class DocumentDouble {
        public function is_built_with_elementor(): bool { return true; }
        public function is_editable_by_current_user(): bool { return true; }
        public function get_main_id(): int { return 7; }
        public function get_elements_data(): array { global $meta; return json_decode($meta[7]['_elementor_data'], true); }
        public function save($data): bool { global $saves, $saveFails, $meta; ++$saves; if ($saveFails) { return false; } $meta[7]['_elementor_data'] = json_encode($data['elements']); return true; }
    }
    $manager = new class { public function get($id, $cache) { return new DocumentDouble(); } };
    \Elementor\Plugin::$instance = (object) ['documents' => $manager];
    $documents = new \Afara\Elementor\Documents(new \Afara\Security\PermissionGate());
    $assert = static function ($condition, $label): void { if (!$condition) { throw new RuntimeException($label); } };
    $denied = static function ($result, $code) use ($assert): void { $assert(is_wp_error($result) && $result->code === $code, $code); };
    $read = $documents->read(7);
    $assert($read['elements'] === $tree && strlen($read['sha256']) === 64, 'read document and checksum');
    foreach (['afara_enabled', 'afara_read_only', 'afara_sandbox_safe_mode'] as $key) {
        $prior = $options[$key]; $options[$key] = $key === 'afara_enabled' ? '0' : '1';
        $denied($documents->update(7, 'heading1', $read['sha256'], 'text', 'After'), 'afara_elementor_write_denied');
        $options[$key] = $prior;
    }
    $options['afara_domain_lock'] = 'wrong.test';
    $assert(!$documents->allowed(7, true), 'domain lock'); $options['afara_domain_lock'] = 'staging.test';
    $property = new ReflectionProperty(\Afara\OAuth\Http::class, 'bearerAuthenticated');
    $property->setValue(null, true);
    $assert(!$documents->allowed(7, true), 'OAuth read scope never authorizes mutations');
    $property->setValue(null, false);
    $environment = 'production'; $assert(!$documents->allowed(7, true), 'production denied'); $environment = 'staging';
    $edit = false; $assert(!$documents->allowed(7, true), 'per-post capability'); $edit = true;
    $ssl = false; $assert(!$documents->allowed(7, true), 'HTTPS required'); $ssl = true;
    $post->post_status = 'publish'; $assert(!$documents->allowed(7, true), 'publishing prohibited'); $post->post_status = 'draft';
    $options['afara_elementor_lock_7'] = 'another-writer';
    $denied($documents->update(7, 'heading1', $read['sha256'], 'text', 'After'), 'afara_elementor_busy'); unset($options['afara_elementor_lock_7']);
    $postLock = true; $denied($documents->update(7, 'heading1', $read['sha256'], 'text', 'After'), 'afara_elementor_editor_lock'); $postLock = false;
    $denied($documents->update(7, 'heading1', str_repeat('0', 64), 'text', 'After'), 'afara_elementor_stale');
    $denied($documents->update(7, 'missing', $read['sha256'], 'text', 'After'), 'afara_elementor_target');
    $denied($documents->update(7, 'image1', $read['sha256'], 'text', 'After'), 'afara_elementor_widget');
    $denied($documents->update(7, 'heading1', $read['sha256'], 'text', '[shortcode]'), 'afara_elementor_text');
    $backupFails = true; $denied($documents->update(7, 'heading1', $read['sha256'], 'text', 'After'), 'afara_elementor_backup'); $backupFails = false;
    $assert($saves === 0, 'denials and backup failures never save');
    $result = $documents->update(7, 'heading1', $read['sha256'], 'text', 'After & more');
    $assert(!is_wp_error($result) && $result['revision_id'] === 99 && $saves === 1, 'successful text edit');
    $assert(json_decode($meta[99]['_elementor_data'], true) === $tree, 'backup stores exact prior tree');
    $after = $documents->read(7);
    $assert($after['elements'][0]['elements'][0]['settings'] === ['title' => 'After &amp; more', 'align' => 'center'], 'preserves unrelated settings and escapes markup');
    $assert($after['elements'][0]['elements'][1] === $tree[0]['elements'][1], 'preserves other widgets');
    $denied($documents->update(7, 'heading1', $read['sha256'], 'text', 'stale'), 'afara_elementor_stale');
    $denied($documents->update(7, 'image1', $after['sha256'], 'image', 666), 'afara_elementor_image');
    $result = $documents->update(7, 'image1', $after['sha256'], 'image', 42);
    $assert(!is_wp_error($result) && $saves === 2, 'image uses media attachment');
    $saveFails = true; $fresh = $documents->read(7);
    $denied($documents->update(7, 'heading1', $fresh['sha256'], 'text', 'Failure'), 'afara_elementor_save_failed');
    $assert($options['afara_sandbox_safe_mode'] === '1', 'save failure enters safe mode');
    $assert(!isset($options['afara_elementor_lock_7']) && $filters === [], 'locks and filters released');
    echo "Elementor document security and edit tests passed\n";
}
