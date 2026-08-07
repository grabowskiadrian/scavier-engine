<?php

namespace Scavier\Detector\Business;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class SocialDetector extends Detector
{
    private const PLATFORMS = [
        'Facebook' => '/facebook\.com\/(?!sharer|share|dialog|plugins)/i',
        'Twitter/X' => '/(twitter\.com|x\.com)\/(?!intent|share|widgets)/i',
        'LinkedIn' => '/linkedin\.com\/(company|in|showcase|school)\/[^\/]+/i',
        'Instagram' => '/instagram\.com\/[^\/]+/i',
        'YouTube' => '/youtube\.com\/(channel|c|@|user)\/[^\/]+/i',
        'TikTok' => '/tiktok\.com\/@[^\/]+/i',
        'GitHub' => '/github\.com\/[^\/]+/i',
        'Pinterest' => '/pinterest\.com\/[^\/]+/i',
    ];

    public static function dependencies(): array
    {
        return [HtmlCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $html = $context->get(HtmlData::class);

        if ($html === null) {
            return null;
        }

        $results = [];
        $found = [];

        // JSON-LD sameAs (highest confidence)
        foreach ($html->jsonLd as $item) {
            $sameAs = $item['sameAs'] ?? [];
            if (is_string($sameAs)) {
                $sameAs = [$sameAs];
            }

            foreach ($sameAs as $url) {
                $this->matchUrl($url, $results, $found, 0.95, 'JSON-LD sameAs');
            }
        }

        // Anchor tags in body (primary source of social links)
        foreach ($html->anchors as $url) {
            $this->matchUrl($url, $results, $found, 0.8, 'Link in page body');
        }

        // OG meta
        foreach ($html->metaProperties as $property => $content) {
            if (str_contains($property, 'url') || str_contains($property, 'site')) {
                $this->matchUrl($content, $results, $found, 0.7, "Meta property: {$property}");
            }
        }

        if (empty($results)) {
            return null;
        }

        $tags = array_column($results, 'platform');

        return ['business' => ['social' => $results], '_tags' => $tags];
    }

    private function matchUrl(string $url, array &$results, array &$found, float $confidence, string $source): void
    {
        foreach (self::PLATFORMS as $platform => $pattern) {
            if (!isset($found[$platform]) && preg_match($pattern, $url, $m)) {
                $found[$platform] = true;
                $results[] = [
                    'platform' => $platform,
                    'url' => $m[0],
                    'confidence' => $confidence,
                    'evidence' => $source,
                ];
            }
        }
    }
}
