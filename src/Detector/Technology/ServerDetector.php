<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HttpCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class ServerDetector extends Detector
{
    private const SERVER_PATTERNS = [
        '/^(Apache)\/?(\S+)?/i',
        '/^(nginx)\/?(\S+)?/i',
        '/^(LiteSpeed)\/?(\S+)?/i',
        '/^(Microsoft-IIS)\/?(\S+)?/i',
        '/^(Caddy)\/?(\S+)?/i',
        '/^(openresty)\/?(\S+)?/i',
        '/^(Tengine)\/?(\S+)?/i',
        '/^(cloudflare)/i',
    ];

    public static function dependencies(): array
    {
        return [
            HttpCollector::class,
        ];
    }

    public function detect(Context $context): ?array
    {
        $http = $context->get(HttpData::class);

        if ($http === null) {
            return null;
        }

        $results = [];

        $server = $http->header('server');
        if ($server !== null) {
            $parsed = $this->parseServer($server);
            $results['web_server'] = [
                'value' => $parsed['name'],
                'version' => $parsed['version'],
                'confidence' => 1.0,
                'evidence' => 'HTTP Server header',
            ];
        }

        $poweredBy = $http->header('x-powered-by');
        if ($poweredBy !== null) {
            $results['runtime'] = [
                'value' => $poweredBy,
                'confidence' => 1.0,
                'evidence' => 'HTTP X-Powered-By header',
            ];
        }

        if (empty($results)) {
            return null;
        }

        $tags = [];
        if (isset($results['web_server'])) {
            $tags[] = $results['web_server']['value'];
        }

        return ['technology' => $results, '_tags' => $tags];
    }

    /**
     * @return array{name: string, version: string|null}
     */
    private function parseServer(string $raw): array
    {
        foreach (self::SERVER_PATTERNS as $pattern) {
            if (preg_match($pattern, $raw, $m)) {
                return [
                    'name' => $m[1],
                    'version' => $m[2] ?? null,
                ];
            }
        }

        return ['name' => $raw, 'version' => null];
    }
}
