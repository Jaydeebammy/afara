<?php
declare(strict_types=1);

namespace Afara\Abilities;

use Afara\Security\PermissionGate;
use Afara\Audit\AuditCallback;
use Afara\Security\PathGuard;
use Afara\Security\ReadablePaths;

final class ReadFile
{
    public function __construct(private readonly PermissionGate $gate) {}

    public function register(): void
    {
        wp_register_ability('afara/read-file', [
            'label' => __('Read source file', 'afara'),
            'description' => __('Read a limited text source file from a theme or plugin.', 'afara'),
            'category' => 'afara',
            'input_schema' => [
                'type' => 'object',
                'properties' => [
                    'path' => ['type' => 'string', 'description' => 'Relative path within wp-content/themes or wp-content/plugins'],
                    'offset' => ['type' => 'integer', 'minimum' => 0, 'default' => 0],
                    'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 16384, 'default' => 8192],
                ],
                'required' => ['path'],
            ],
            'output_schema' => [
                'type' => 'object',
                'properties' => [
                    'path' => ['type' => 'string'],
                    'content' => ['type' => 'string'],
                    'bytes_read' => ['type' => 'integer'],
                    'truncated' => ['type' => 'boolean'],
                ],
            ],
            'permission_callback' => fn (): bool => $this->gate->canRead(),
            'execute_callback' => AuditCallback::wrap(static function (array $input) {
                $path = (string) ($input['path'] ?? '');
                $file = (new ReadablePaths(new PathGuard(ABSPATH)))->resolve($path);
                if ($file === null) {
                    return new \WP_Error('afara_path_denied', 'Path is not permitted.');
                }
                $size = filesize($file);
                if ($size === false || $size > 1048576) {
                    return new \WP_Error('afara_file_limit', 'File is too large to inspect.');
                }
                $offset = max(0, (int) ($input['offset'] ?? 0));
                $limit = min(16384, max(1, (int) ($input['limit'] ?? 8192)));
                $handle = fopen($file, 'rb');
                if ($handle === false) {
                    return new \WP_Error('afara_read_failed', 'Unable to open file.');
                }
                try {
                    if (fseek($handle, $offset) !== 0) {
                        return new \WP_Error('afara_offset_invalid', 'Invalid offset.');
                    }
                    $content = fread($handle, $limit);
                    if ($content === false) {
                        return new \WP_Error('afara_read_failed', 'Unable to read file.');
                    }
                } finally {
                    fclose($handle);
                }
                if (!preg_match('//u', $content)) {
                    return new \WP_Error('afara_binary_or_partial_utf8', 'Requested range is not valid UTF-8 text.');
                }
                return [
                    'path' => $path,
                    'content' => $content,
                    'bytes_read' => strlen($content),
                    'truncated' => ($offset + strlen($content)) < $size,
                ];
            }, 'afara/read-file'),
            'meta' => ['show_in_rest' => false, 'mcp' => ['public' => false], 'annotations' => ['readonly' => true, 'destructive' => false]],
        ]);
    }
}
