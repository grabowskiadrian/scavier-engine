<?php

namespace Scavier\Adapter;

use Scavier\Engine\Scavier;

final class ApiHandler
{
    public function __construct(
        private Scavier $scavier,
    ) {
    }

    /**
     * @return array{status: int, body: array}
     */
    public function handle(array $query): array
    {
        $url = $query['url'] ?? null;

        if ($url === null || $url === '') {
            return [
                'status' => 400,
                'body' => [
                    'success' => false,
                    'error' => 'Missing required parameter: url',
                    'usage' => '/analyze?url=https://example.com&detectors=server,library',
                    'available_detectors' => array_keys($this->scavier->availableDetectors()),
                ],
            ];
        }

        $detectors = [];

        if (isset($query['detectors']) && $query['detectors'] !== '') {
            $available = $this->scavier->availableDetectors();
            $requested = array_map('trim', explode(',', $query['detectors']));

            foreach ($requested as $name) {
                $name = strtolower($name);

                if (!isset($available[$name])) {
                    return [
                        'status' => 400,
                        'body' => [
                            'success' => false,
                            'error' => "Unknown detector: {$name}",
                            'available_detectors' => array_keys($available),
                        ],
                    ];
                }

                $detectors[] = $available[$name];
            }
        }

        $result = $this->scavier->analyze($url, $detectors);

        if (!$result['success']) {
            return [
                'status' => 400,
                'body' => [
                    'success' => false,
                    'url' => $url,
                    'error' => $result['error'],
                ],
            ];
        }

        return [
            'status' => 200,
            'body' => [
                'success' => true,
                'url' => $url,
                'data' => $result['data'],
            ],
        ];
    }
}
