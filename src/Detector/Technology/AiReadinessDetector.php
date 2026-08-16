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

        // llms.txt — must not be HTML (redirect to homepage)
        $llmsBody = $discovery->exists('/llms.txt') ? $discovery->body('/llms.txt') : null;
        $llmsValid = $llmsBody !== null && !$this->isHtml($llmsBody);

        $result['llms_txt'] = [
            'exists' => $llmsValid,
        ];

        if ($llmsValid) {
            if (preg_match('/^#\s+(.+)/m', $llmsBody, $m)) {
                $result['llms_txt']['title'] = trim($m[1]);
            }
            $result['llms_txt']['size_bytes'] = strlen($llmsBody);
        }

        // MCP server — must be valid JSON
        $mcpBody = $discovery->exists('/.well-known/mcp.json') ? $discovery->body('/.well-known/mcp.json') : null;
        $mcpData = $mcpBody !== null ? json_decode($mcpBody, true) : null;
        $mcpValid = is_array($mcpData);

        $result['mcp_server'] = [
            'exists' => $mcpValid,
        ];

        if ($mcpValid) {
            $result['mcp_server']['endpoint'] = $mcpData['url'] ?? $mcpData['endpoint'] ?? null;
        }

        // API discovery — must be valid JSON
        $apiBody = null;
        if ($discovery->exists('/openapi.json')) {
            $apiBody = $discovery->body('/openapi.json');
        } elseif ($discovery->exists('/swagger.json')) {
            $apiBody = $discovery->body('/swagger.json');
        }
        $apiData = $apiBody !== null ? json_decode($apiBody, true) : null;
        $hasOpenApi = is_array($apiData);

        $result['api_docs'] = [
            'exists' => $hasOpenApi,
        ];

        if ($hasOpenApi) {
            $result['api_docs']['title'] = $apiData['info']['title'] ?? null;
            $result['api_docs']['version'] = $apiData['info']['version'] ?? null;
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

    private function isHtml(string $body): bool
    {
        return (bool) preg_match('/<(!DOCTYPE|html|head|body)/i', $body);
    }
}
