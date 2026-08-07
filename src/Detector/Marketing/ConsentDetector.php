<?php

namespace Scavier\Detector\Marketing;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class ConsentDetector extends Detector
{
    private const SCRIPT_PATTERNS = [
        'Cookiebot' => '/cookiebot\.com/i',
        'OneTrust' => '/onetrust\.com|optanon|cookielaw\.org/i',
        'CookieYes' => '/cookieyes\.com/i',
        'Quantcast' => '/quantcast\.com\/choice/i',
        'Osano' => '/osano\.com/i',
        'Termly' => '/termly\.io/i',
        'iubenda' => '/iubenda\.com/i',
        'Cookie Notice' => '/cookie-notice/i',
        'Complianz' => '/complianz/i',
        'CookieScript' => '/cookie-script\.com/i',
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

        foreach (self::SCRIPT_PATTERNS as $name => $pattern) {
            $matches = $html->scriptsMatching($pattern);

            if (!empty($matches)) {
                $results[] = [
                    'value' => $name,
                    'confidence' => 0.9,
                    'evidence' => 'Script src: ' . $matches[0],
                ];
            }
        }

        if (empty($results)) {
            return null;
        }

        $tags = array_column($results, 'value');

        return ['marketing' => ['consent' => $results], '_tags' => $tags];
    }
}
