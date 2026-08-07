<?php

namespace Scavier\Adapter;

use Scavier\Engine\Scavier;

final class McpHandler
{
    private const PROTOCOL_VERSION = '2024-11-05';
    private const SERVER_NAME = 'scavier';
    private const SERVER_VERSION = Scavier::VERSION;

    public function __construct(
        private Scavier $scavier,
    ) {
    }

    public function handle(string $body): ?array
    {
        $request = json_decode($body, true);

        if ($request === null) {
            return self::error(null, -32700, 'Parse error');
        }

        if (!isset($request['method'])) {
            return self::error($request['id'] ?? null, -32600, 'Invalid request');
        }

        return match ($request['method']) {
            'initialize' => $this->initialize($request),
            'notifications/initialized' => null,
            'tools/list' => $this->toolsList($request),
            'tools/call' => $this->toolsCall($request),
            'ping' => self::result($request['id'] ?? null, []),
            default => self::error($request['id'] ?? null, -32601, "Unknown method: {$request['method']}"),
        };
    }

    private function initialize(array $request): array
    {
        return self::result($request['id'] ?? null, [
            'protocolVersion' => self::PROTOCOL_VERSION,
            'capabilities' => [
                'tools' => ['listChanged' => false],
            ],
            'serverInfo' => [
                'name' => self::SERVER_NAME,
                'version' => self::SERVER_VERSION,
            ],
        ]);
    }

    private function toolsList(array $request): array
    {
        $detectorNames = array_keys($this->scavier->availableDetectors());

        return self::result($request['id'] ?? null, [
            'tools' => [
                [
                    'name' => 'analyze',
                    'description' => 'Analyze a website and detect its technology stack, server infrastructure, libraries, and more.',
                    'inputSchema' => [
                        'type' => 'object',
                        'properties' => [
                            'url' => [
                                'type' => 'string',
                                'description' => 'The URL to analyze (e.g. https://example.com)',
                            ],
                            'detectors' => [
                                'type' => 'string',
                                'description' => 'Comma-separated list of detectors to use. Available: ' . implode(', ', $detectorNames) . '. Omit to use all.',
                            ],
                        ],
                        'required' => ['url'],
                    ],
                ],
            ],
        ]);
    }

    private function toolsCall(array $request): array
    {
        $id = $request['id'] ?? null;
        $params = $request['params'] ?? [];
        $toolName = $params['name'] ?? '';
        $args = $params['arguments'] ?? [];

        if ($toolName !== 'analyze') {
            return self::result($id, [
                'content' => [['type' => 'text', 'text' => "Unknown tool: {$toolName}"]],
                'isError' => true,
            ]);
        }

        $url = $args['url'] ?? null;

        if ($url === null || $url === '') {
            return self::result($id, [
                'content' => [['type' => 'text', 'text' => 'Missing required argument: url']],
                'isError' => true,
            ]);
        }

        $detectors = [];

        if (isset($args['detectors']) && $args['detectors'] !== '') {
            $available = $this->scavier->availableDetectors();
            $requested = array_map('trim', explode(',', $args['detectors']));

            foreach ($requested as $name) {
                $name = strtolower($name);

                if (!isset($available[$name])) {
                    return self::result($id, [
                        'content' => [['type' => 'text', 'text' => "Unknown detector: {$name}. Available: " . implode(', ', array_keys($available))]],
                        'isError' => true,
                    ]);
                }

                $detectors[] = $available[$name];
            }
        }

        $result = $this->scavier->analyze($url, $detectors);

        if (!$result['success']) {
            return self::result($id, [
                'content' => [['type' => 'text', 'text' => $result['error']]],
                'isError' => true,
            ]);
        }

        return self::result($id, [
            'content' => [[
                'type' => 'text',
                'text' => json_encode(['url' => $url, 'data' => $result['data']], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            ]],
        ]);
    }

    private static function result(int|string|null $id, array $result): array
    {
        return [
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => $result,
        ];
    }

    private static function error(int|string|null $id, int $code, string $message): array
    {
        return [
            'jsonrpc' => '2.0',
            'id' => $id,
            'error' => [
                'code' => $code,
                'message' => $message,
            ],
        ];
    }
}
