<?php
declare(strict_types=1);

namespace Afara\Abilities;

use Afara\Security\PermissionGate;
use Afara\Security\PathGuard;
use Afara\Security\ReadablePaths;

final class ListDirectory
{
    public function __construct(private readonly PermissionGate $gate) {}

    public function register(): void
    {
        wp_register_ability('afara/list-directory', [
            'label' => __('List source directory', 'afara'),
            'description' => __('List visible files in one plugin or theme directory.', 'afara'),
            'category' => 'afara',
            'input_schema' => [
                'type' => 'object',
                'properties' => [
                    'path' => ['type' => 'string'],
                    'limit' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 50],
                ],
                'required' => ['path'],
            ],
            'output_schema' => [
                'type' => 'object',
                'properties' => [
                    'path' => ['type' => 'string'],
                    'entries' => ['type' => 'array', 'items' => [
                        'type' => 'object',
                        'properties' => [
                            'name' => ['type' => 'string'],
                            'type' => ['type' => 'string'],
                        ],
                    ]],
                    'truncated' => ['type' => 'boolean'],
                ],
            ],
            'permission_callback' => fn (): bool => $this->gate->canRead(),
            'execute_callback' => static function (array $input) {
                $path = (string) ($input['path'] ?? '');
                $scope = new ReadablePaths(new PathGuard(ABSPATH));
                $directory = $scope->resolve($path, true);
                if ($directory === null) {
                    return new \WP_Error('afara_path_denied', 'Path is not permitted.');
                }
                $entries = [];
                $limit = min(100, max(1, (int) ($input['limit'] ?? 50)));
                $iterator = new \FilesystemIterator($directory, \FilesystemIterator::SKIP_DOTS);
                $truncated = false;
                foreach ($iterator as $entry) {
                    $childPath = $path . '/' . $entry->getFilename();
                    $asDirectory = $scope->resolve($childPath, true);
                    $asFile = $scope->resolve($childPath);
                    if ($asDirectory === null && $asFile === null) {
                        continue;
                    }
                    if (count($entries) >= $limit) {
                        $truncated = true;
                        break;
                    }
                    $entries[] = ['name' => $entry->getFilename(), 'type' => $asDirectory !== null ? 'directory' : 'file'];
                }
                return ['path' => $path, 'entries' => $entries, 'truncated' => $truncated];
            },
            'meta' => ['show_in_rest' => false, 'mcp' => ['public' => false], 'annotations' => ['readonly' => true, 'destructive' => false]],
        ]);
    }
}
