<?php

namespace Scavier\Detector\Marketing;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class AdNetworkDetector extends Detector
{
    private const SCRIPT_PATTERNS = [
        'Google AdSense' => '/pagead2\.googlesyndication\.com/i',
        'Google Ad Manager' => '/securepubads\.g\.doubleclick\.net/i',
        'Google Ads' => '/googleads\.g\.doubleclick\.net|googleadservices\.com\/pagead/i',
        'Amazon Publisher Services' => '/c\.amazon-adsystem\.com/i',
        'Media.net' => '/contextual\.media\.net/i',
        'Ezoic' => '/ezoic\.net|ezojs\.com/i',
        'Mediavine' => '/mediavine\.com|scripts\.mediavine/i',
        'AdThrive (Raptive)' => '/adthrive\.com|raptive\.com/i',
        'Taboola' => '/cdn\.taboola\.com/i',
        'Outbrain' => '/outbrain\.com\/outbrain\.js/i',
        'Carbon Ads' => '/srv\.carbonads\.net|carbonads\.com/i',
        'BuySellAds' => '/buysellads\.com/i',
        'PropellerAds' => '/propellerads\.com/i',
    ];

    private const INLINE_PATTERNS = [
        'Google AdSense' => '/adsbygoogle/i',
        'Google Ad Manager' => '/googletag\.cmd\.push/i',
        'Taboola' => '/taboola\.push/i',
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

        foreach (self::SCRIPT_PATTERNS as $name => $pattern) {
            $matches = $html->scriptsMatching($pattern);
            if (!empty($matches) && !isset($found[$name])) {
                $found[$name] = true;
                $results[] = [
                    'value' => $name,
                    'confidence' => 0.9,
                    'evidence' => 'Script src: ' . $matches[0],
                ];
            }
        }

        foreach (self::INLINE_PATTERNS as $name => $pattern) {
            if (!isset($found[$name]) && $html->hasInlineScriptMatching($pattern)) {
                $found[$name] = true;
                $results[] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => 'Inline script pattern',
                ];
            }
        }

        if (empty($results)) {
            return null;
        }

        $tags = array_column($results, 'value');

        return ['marketing' => ['advertising' => $results], '_tags' => $tags];
    }
}
