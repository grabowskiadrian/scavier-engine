<?php

namespace Scavier\Detector\Seo;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class SitemapDetector extends Detector
{
    public static function dependencies(): array
    {
        return [DiscoveryCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $discovery = $context->get(DiscoveryData::class);

        if ($discovery === null) {
            return null;
        }

        $exists = $discovery->exists('/sitemap.xml');
        $body = $discovery->body('/sitemap.xml');

        $result = [
            'exists' => $exists,
            'confidence' => 1.0,
            'evidence' => $exists ? 'sitemap.xml found' : 'sitemap.xml not found',
        ];

        if ($exists && $body !== null) {
            // Check if it's a sitemap index
            $isIndex = str_contains($body, '<sitemapindex');
            $result['is_index'] = $isIndex;

            // Count URLs or sub-sitemaps via XML parsing
            $prev = libxml_use_internal_errors(true);
            $xml = simplexml_load_string($body);
            libxml_use_internal_errors($prev);

            if ($xml !== false) {
                if ($isIndex) {
                    $result['sitemap_count'] = count($xml->sitemap ?? []);
                } else {
                    $result['url_count'] = count($xml->url ?? []);
                }
            }
        }

        return ['seo' => ['sitemap' => $result]];
    }
}
