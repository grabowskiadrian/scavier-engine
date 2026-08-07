<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Detector\Seo\RobotsDetector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class AiReadinessDetector extends Detector
{
    public static function dependencies(): array
    {
        return [DiscoveryCollector::class, RobotsDetector::class];
    }

    public function detect(Context $context): ?array
    {
        $discovery = $context->get(DiscoveryData::class);

        if ($discovery === null) {
            return null;
        }

        $result = [];

        // llms.txt
        $result['llms_txt'] = [
            'exists' => $discovery->exists('/llms.txt'),
        ];

        if ($discovery->exists('/llms.txt')) {
            $body = $discovery->body('/llms.txt');
            if ($body !== null) {
                // Extract title (first # heading)
                if (preg_match('/^#\s+(.+)/m', $body, $m)) {
                    $result['llms_txt']['title'] = trim($m[1]);
                }
                $result['llms_txt']['size_bytes'] = strlen($body);
            }
        }

        // MCP server
        $result['mcp_server'] = [
            'exists' => $discovery->exists('/.well-known/mcp.json'),
        ];

        if ($discovery->exists('/.well-known/mcp.json')) {
            $body = $discovery->body('/.well-known/mcp.json');
            if ($body !== null) {
                $data = json_decode($body, true);
                if (is_array($data)) {
                    $result['mcp_server']['endpoint'] = $data['url'] ?? $data['endpoint'] ?? null;
                }
            }
        }

        // API discovery
        $hasOpenApi = $discovery->exists('/openapi.json') || $discovery->exists('/swagger.json');
        $result['api_docs'] = [
            'exists' => $hasOpenApi,
        ];

        if ($hasOpenApi) {
            $body = $discovery->body('/openapi.json') ?? $discovery->body('/swagger.json');
            if ($body !== null) {
                $data = json_decode($body, true);
                if (is_array($data)) {
                    $result['api_docs']['title'] = $data['info']['title'] ?? null;
                    $result['api_docs']['version'] = $data['info']['version'] ?? null;
                }
            }
        }

        // AI bot blocking from robots detector
        $robotsResult = $context->getDetectorResult(RobotsDetector::class);
        $aiBots = $robotsResult['seo']['robots']['ai_bots'] ?? null;

        if ($aiBots !== null) {
            $result['ai_crawler_policy'] = [
                'blocks_ai_crawlers' => $aiBots['blocks_ai_crawlers'],
                'blocked_bots' => $aiBots['blocked'] ?? [],
            ];
        }

        return ['technology' => ['ai_readiness' => $result]];
    }
}
