<?php

namespace Scavier\Detector\Marketing;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class AbTestingDetector extends Detector
{
    private const SCRIPT_PATTERNS = [
        'Optimizely' => '/cdn\.optimizely\.com/i',
        'VWO' => '/dev\.visualwebsiteoptimizer\.com|\.vwo\.com\//i',
        'Google Optimize' => '/optimize\.google\.com|googleoptimize\.com/i',
        'LaunchDarkly' => '/launchdarkly\.com/i',
        'Split.io' => '/cdn\.split\.io/i',
        'Statsig' => '/statsig\.com/i',
        'AB Tasty' => '/abtasty\.com/i',
        'Convert' => '/cdn-\d+\.convertexperiments\.com/i',
        'Kameleoon' => '/kameleoon\.eu/i',
    ];

    private const INLINE_PATTERNS = [
        'Optimizely' => '/optimizely\.push/i',
        'VWO' => '/VWO\s*=|_vwo_code/i',
        'LaunchDarkly' => '/LDClient/i',
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

        return ['marketing' => ['ab_testing' => $results], '_tags' => $tags];
    }
}
