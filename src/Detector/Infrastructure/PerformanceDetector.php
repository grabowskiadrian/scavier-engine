<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class PerformanceDetector extends Detector
{
    public static function dependencies(): array
    {
        return [HtmlCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $http = $context->get(HttpData::class);
        $html = $context->get(HtmlData::class);

        if ($http === null) {
            return null;
        }

        $result = [];

        if ($http->responseTime !== null) {
            $result['total_time'] = $http->responseTime;
        }

        if ($http->dnsTime !== null) {
            $result['dns_lookup'] = $http->dnsTime;
        }

        if ($http->connectTime !== null) {
            $result['tcp_connect'] = $http->connectTime;
        }

        if ($http->ttfb !== null) {
            $result['ttfb'] = $http->ttfb;

            // TTFB grading per Google Web Vitals thresholds
            $result['ttfb_grade'] = match (true) {
                $http->ttfb <= 0.8 => 'good',
                $http->ttfb <= 1.8 => 'needs_improvement',
                default => 'poor',
            };
        }

        // Page weight
        $result['page_weight_bytes'] = strlen($http->body);

        // Asset counts
        if ($html !== null) {
            $result['script_count'] = count($html->scripts);
            $result['stylesheet_count'] = count($html->stylesheets);
            $result['inline_script_count'] = count($html->inlineScripts);
        }

        // HTTP version
        if ($http->httpVersion !== null) {
            $result['http_version'] = match ($http->httpVersion) {
                CURL_HTTP_VERSION_1_0 => '1.0',
                CURL_HTTP_VERSION_1_1 => '1.1',
                CURL_HTTP_VERSION_2_0, CURL_HTTP_VERSION_2 => '2',
                30 => '3', // CURL_HTTP_VERSION_3
                default => (string) $http->httpVersion,
            };
        }

        if (empty($result)) {
            return null;
        }

        $result['confidence'] = 1.0;
        $result['evidence'] = 'HTTP response timing';

        return ['infrastructure' => ['performance' => $result]];
    }
}
