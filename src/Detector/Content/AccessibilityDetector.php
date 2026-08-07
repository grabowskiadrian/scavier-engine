<?php

namespace Scavier\Detector\Content;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class AccessibilityDetector extends Detector
{
    private const OVERLAY_PATTERNS = [
        'AccessiBe' => '/accessibe\.com|acsbapp\.com/i',
        'UserWay' => '/userway\.org/i',
        'AudioEye' => '/audioeye\.com/i',
        'EqualWeb' => '/equalweb\.com/i',
        'MaxAccess' => '/maxaccess\.io/i',
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

        $checks = [];

        // html lang
        $checks['lang_attribute'] = $html->htmlLang !== null;

        // viewport meta
        $checks['viewport'] = $html->metaTag('viewport') !== null;

        // Check for accessibility overlay tools
        $overlays = [];
        $allSources = array_merge($html->scripts, $html->stylesheets);

        foreach (self::OVERLAY_PATTERNS as $name => $pattern) {
            foreach ($allSources as $src) {
                if (preg_match($pattern, $src)) {
                    $overlays[] = $name;
                    break;
                }
            }
        }

        $checks['overlay_tool'] = !empty($overlays);

        $passed = count(array_filter($checks));
        $total = count($checks);

        $result = [
            'checks' => $checks,
            'passed' => $passed,
            'total' => $total,
            'confidence' => 1.0,
            'evidence' => 'HTML inspection',
        ];

        if (!empty($overlays)) {
            $result['overlay_tools'] = $overlays;
        }

        return ['content' => ['accessibility' => $result], '_tags' => $overlays];
    }
}
