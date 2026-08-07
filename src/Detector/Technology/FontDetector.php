<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class FontDetector extends Detector
{
    private const STYLESHEET_PATTERNS = [
        'Google Fonts' => '/fonts\.googleapis\.com/i',
        'Adobe Fonts' => '/use\.typekit\.net/i',
        'Bunny Fonts' => '/fonts\.bunny\.net/i',
    ];

    private const PRECONNECT_PATTERNS = [
        'Google Fonts' => '/fonts\.gstatic\.com/i',
        'Adobe Fonts' => '/use\.typekit\.net/i',
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

        // Check stylesheets
        foreach (self::STYLESHEET_PATTERNS as $name => $pattern) {
            foreach ($html->stylesheets as $href) {
                if (!isset($found[$name]) && preg_match($pattern, $href)) {
                    $found[$name] = true;
                    $entry = [
                        'value' => $name,
                        'confidence' => 0.95,
                        'evidence' => "Stylesheet: {$href}",
                    ];

                    // Extract font families from Google Fonts URL
                    if ($name === 'Google Fonts' && preg_match_all('/family=([^&:]+)/', $href, $fm)) {
                        $entry['families'] = array_map(fn($f) => urldecode(str_replace('+', ' ', $f)), $fm[1]);
                    }

                    $results[] = $entry;
                }
            }
        }

        // Check preconnect links
        foreach (self::PRECONNECT_PATTERNS as $name => $pattern) {
            if (!isset($found[$name])) {
                foreach ($html->links as $link) {
                    if (in_array($link['rel'], ['preconnect', 'dns-prefetch']) && preg_match($pattern, $link['href'])) {
                        $found[$name] = true;
                        $results[] = [
                            'value' => $name,
                            'confidence' => 0.7,
                            'evidence' => "Preconnect: {$link['href']}",
                        ];
                        break;
                    }
                }
            }
        }

        if (empty($results)) {
            return null;
        }

        $tags = array_column($results, 'value');

        return ['technology' => ['fonts' => $results], '_tags' => $tags];
    }
}
