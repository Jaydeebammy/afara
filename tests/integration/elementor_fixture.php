<?php
// Disposable CI fixture only; invoke with wp --user=admin eval-file.
if (!defined('WP_CLI') || !WP_CLI || !class_exists('Elementor\\Plugin')) { exit(1); }
$document = \Elementor\Plugin::$instance->documents->create('wp-page', ['post_title' => 'Afara Elementor fixture', 'post_status' => 'draft']);
if (is_wp_error($document)) { throw new RuntimeException('Fixture creation failed'); }
$id = $document->get_main_id();
$elements = [['id' => 'abcdef0', 'elType' => 'container', 'settings' => [], 'elements' => [
    ['id' => 'abcdef1', 'elType' => 'widget', 'widgetType' => 'heading', 'settings' => ['title' => 'Original heading', 'align' => 'center'], 'elements' => []],
    ['id' => 'abcdef2', 'elType' => 'widget', 'widgetType' => 'image', 'settings' => [], 'elements' => []],
    ['id' => 'abcdef3', 'elType' => 'widget', 'widgetType' => 'button', 'settings' => ['text' => 'Original button'], 'elements' => []],
]]];
if (!$document->save(['elements' => $elements])) { throw new RuntimeException('Fixture save failed'); }
$upload = wp_upload_bits('afara-elementor-fixture.png', null, base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a5FoAAAAASUVORK5CYII='));
if ($upload['error']) { throw new RuntimeException('Fixture image failed'); }
$attachment = wp_insert_attachment(['post_mime_type' => 'image/png', 'post_title' => 'Afara image fixture', 'post_status' => 'inherit'], $upload['file']);
if (is_wp_error($attachment) || !$attachment) { throw new RuntimeException('Fixture attachment failed'); }
update_attached_file($attachment, $upload['file']);
echo wp_json_encode(['post_id' => $id, 'attachment_id' => $attachment]);
