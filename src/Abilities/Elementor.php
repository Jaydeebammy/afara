<?php
declare(strict_types=1);

namespace Afara\Abilities;

use Afara\Audit\ActivityLog;
use Afara\Audit\AuditCallback;
use Afara\Elementor\Documents;
use Afara\Security\PermissionGate;

final class Elementor
{
    public const ABILITIES = ['afara/elementor-document', 'afara/elementor-update-text', 'afara/elementor-update-image'];

    public function __construct(private readonly PermissionGate $gate) {}

    public function register(): void
    {
        $documents = new Documents($this->gate);
        foreach (self::ABILITIES as $name) {
            $write = $name !== self::ABILITIES[0];
            $image = $name === self::ABILITIES[2];
            $properties = ['post_id' => ['type' => 'integer', 'minimum' => 1]];
            if ($write) {
                $properties += [
                    'element_id' => ['type' => 'string', 'pattern' => '^[a-zA-Z0-9_-]{1,64}$'],
                    'expected_sha256' => ['type' => 'string', 'pattern' => '^[a-f0-9]{64}$'],
                ];
                $properties += $image
                    ? ['attachment_id' => ['type' => 'integer', 'minimum' => 1]]
                    : ['text' => ['type' => 'string', 'maxLength' => 16384]];
            }
            wp_register_ability($name, [
                'label' => __($write ? ($image ? 'Update Elementor image' : 'Update Elementor text') : 'Read Elementor document', 'afara'),
                'description' => __($write ? 'Edit one existing classic widget on a draft post/page. Requires write mode, safe mode off, staging/development, Application Password authentication and a fresh document checksum. Creates a revision backup; never publishes.' : 'Read an editable Elementor post/page and its checksum before a controlled draft edit.', 'afara'),
                'category' => 'afara',
                'input_schema' => ['type' => 'object', 'properties' => $properties, 'required' => array_keys($properties), 'additionalProperties' => false],
                'output_schema' => ['type' => 'object', 'properties' => $write ? [
                    'post_id' => ['type' => 'integer'], 'element_id' => ['type' => 'string'],
                    'sha256' => ['type' => 'string'], 'revision_id' => ['type' => 'integer'],
                ] : [
                    'post_id' => ['type' => 'integer'], 'sha256' => ['type' => 'string'],
                    'elements' => ['type' => 'array', 'items' => ['type' => 'object']],
                ]],
                'permission_callback' => static function ($input = []) use ($documents, $write, $name): bool {
                    $allowed = $documents->allowed((int) ($input['post_id'] ?? 0), $write);
                    if (!$allowed) { ActivityLog::refused($write ? 'afara_elementor_write_denied' : 'afara_elementor_denied', $name); }
                    return $allowed;
                },
                'execute_callback' => AuditCallback::wrap(static function (array $input) use ($documents, $write, $image) {
                    if (!$write) { return $documents->read((int) $input['post_id']); }
                    return $documents->update((int) $input['post_id'], $input['element_id'], $input['expected_sha256'],
                        $image ? 'image' : 'text', $input[$image ? 'attachment_id' : 'text']);
                }, $name),
                'meta' => ['show_in_rest' => false, 'mcp' => ['public' => false],
                    'annotations' => ['readonly' => !$write, 'destructive' => $write]],
            ]);
        }
    }
}
