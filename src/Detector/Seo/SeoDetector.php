<?php

namespace Scavier\Detector\Seo;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class SeoDetector extends Detector
{
    public static function dependencies(): array
    {
        return [
            HtmlCollector::class,
            RobotsDetector::class,
            SitemapDetector::class,
        ];
    }

    public function detect(Context $context): ?array
    {
        $html = $context->get(HtmlData::class);

        if ($html === null) {
            return null;
        }

        $checks = [];

        // Title
        $titleLen = $html->title !== null ? mb_strlen($html->title) : 0;
        $checks['title'] = [
            'present' => $html->title !== null && $html->title !== '',
            'value' => $html->title,
            'length' => $titleLen,
        ];
        if ($titleLen > 0) {
            $checks['title']['optimal'] = $titleLen >= 30 && $titleLen <= 60;
        }

        // Meta description
        $description = $html->metaTag('description');
        $descLen = $description !== null ? mb_strlen($description) : 0;
        $checks['meta_description'] = [
            'present' => $description !== null && $description !== '',
            'value' => $description,
            'length' => $descLen,
        ];
        if ($descLen > 0) {
            $checks['meta_description']['optimal'] = $descLen >= 120 && $descLen <= 160;
        }

        // Canonical
        $canonical = null;
        foreach ($html->links as $link) {
            if ($link['rel'] === 'canonical') {
                $canonical = $link['href'];
                break;
            }
        }
        $checks['canonical'] = [
            'present' => $canonical !== null,
            'value' => $canonical,
        ];

        // Open Graph
        $ogTags = array_filter($html->metaProperties, fn($v, $k) => str_starts_with($k, 'og:'), ARRAY_FILTER_USE_BOTH);
        $checks['open_graph'] = [
            'present' => !empty($ogTags),
            'tags' => array_keys($ogTags),
        ];

        // Twitter Card
        $twitterTags = array_filter($html->metaProperties, fn($v, $k) => str_starts_with($k, 'twitter:'), ARRAY_FILTER_USE_BOTH);
        if (empty($twitterTags)) {
            $twitterTags = array_filter($html->meta, fn($v, $k) => str_starts_with($k, 'twitter:'), ARRAY_FILTER_USE_BOTH);
        }
        $checks['twitter_card'] = [
            'present' => !empty($twitterTags),
            'tags' => array_keys($twitterTags),
        ];

        // Viewport
        $viewport = $html->metaTag('viewport');
        $checks['viewport'] = [
            'present' => $viewport !== null,
            'value' => $viewport,
        ];

        // Language
        $checks['lang'] = [
            'present' => $html->htmlLang !== null,
            'value' => $html->htmlLang,
        ];

        // JSON-LD
        $checks['structured_data'] = [
            'present' => !empty($html->jsonLd),
            'count' => count($html->jsonLd),
        ];

        // Meta robots
        $metaRobots = $html->metaTag('robots');
        $hasBlockingDirective = $metaRobots !== null && preg_match('/noindex|nofollow/i', $metaRobots);
        $checks['meta_robots'] = [
            'present' => !$hasBlockingDirective,
            'value' => $metaRobots,
        ];
        if ($metaRobots !== null) {
            $checks['meta_robots']['noindex'] = (bool) preg_match('/noindex/i', $metaRobots);
            $checks['meta_robots']['nofollow'] = (bool) preg_match('/nofollow/i', $metaRobots);
        }

        // Robots/Sitemap from detector results
        $robotsResult = $context->getDetectorResult(RobotsDetector::class);
        $sitemapResult = $context->getDetectorResult(SitemapDetector::class);

        $checks['robots_txt'] = [
            'present' => $robotsResult !== null && ($robotsResult['seo']['robots']['exists'] ?? false),
        ];

        $checks['sitemap'] = [
            'present' => $sitemapResult !== null && ($sitemapResult['seo']['sitemap']['exists'] ?? false),
        ];

        $total = count($checks);
        $passed = count(array_filter($checks, fn($c) => $c['present']));

        return [
            'seo' => [
                'overview' => [
                    'checks' => $checks,
                ],
            ],
            'audit' => [
                'seo_score' => [
                    'score' => round($passed / $total, 2),
                    'passed' => $passed,
                    'total' => $total,
                ],
            ],
        ];
    }
}
