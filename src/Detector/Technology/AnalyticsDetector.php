<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class AnalyticsDetector extends Detector
{
    private const SCRIPT_PATTERNS = [
        // Analytics
        'Google Analytics (GA4)' => '/googletagmanager\.com\/gtag/i',
        'Google Analytics (Universal)' => '/google-analytics\.com\/analytics\.js/i',
        'Google Tag Manager' => '/googletagmanager\.com\/gtm\.js/i',
        'Facebook Pixel' => '/connect\.facebook\.net\/.*\/fbevents\.js/i',
        'Matomo' => '/matomo\.js|piwik\.js/i',
        'Plausible' => '/plausible\.io\/js/i',
        'Fathom' => '/cdn\.usefathom\.com/i',
        'Mixpanel' => '/cdn\.mxpnl\.com|api\.mixpanel\.com/i',
        'Segment' => '/cdn\.segment\.com|cdn\.segment\.io/i',
        'Amplitude' => '/cdn\.amplitude\.com/i',
        'Heap' => '/cdn\.heapanalytics\.com/i',
        'PostHog' => '/posthog\.com|ph\.js/i',
        // Tag management
        'Tealium' => '/tags\.tiqcdn\.com|tealium/i',
        'Adobe Launch' => '/assets\.adobedtm\.com|launch-/i',
        // Session recording / heatmaps (= invests in UX)
        'Hotjar' => '/static\.hotjar\.com/i',
        'Clarity' => '/clarity\.ms/i',
        'FullStory' => '/fullstory\.com\/s\/fs\.js/i',
        'LogRocket' => '/cdn\.logrocket\.(com|io)/i',
        'Mouseflow' => '/cdn\.mouseflow\.com/i',
        'Smartlook' => '/web-sdk\.smartlook\.com|rec\.smartlook/i',
        'Lucky Orange' => '/cdn\.luckyorange\.com/i',
    ];

    private const INLINE_PATTERNS = [
        'Google Analytics (GA4)' => '/gtag\s*\(\s*[\'"]config[\'"]\s*,\s*[\'"]G-/i',
        'Google Analytics (Universal)' => '/ga\s*\(\s*[\'"]create[\'"]\s*,\s*[\'"]UA-/i',
        'Google Tag Manager' => '/GTM-[A-Z0-9]+/i',
        'Facebook Pixel' => '/fbq\s*\(\s*[\'"]init[\'"]/i',
        'Hotjar' => '/hj\s*\(\s*[\'"]stateChange[\'"]/i',
        'Matomo' => '/_paq\.push/i',
        'Yandex Metrica' => '/ym\s*\(\s*\d+\s*,\s*[\'"]init[\'"]|mc\.yandex\.ru\/metrika/i',
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

        // Script URL patterns
        foreach (self::SCRIPT_PATTERNS as $name => $pattern) {
            $matches = $html->scriptsMatching($pattern);
            if (!empty($matches) && !isset($found[$name])) {
                $found[$name] = true;
                $results[] = [
                    'value' => $name,
                    'confidence' => 0.95,
                    'evidence' => 'Script src: ' . $matches[0],
                ];
            }
        }

        // Inline script patterns
        foreach (self::INLINE_PATTERNS as $name => $pattern) {
            if (!isset($found[$name]) && $html->hasInlineScriptMatching($pattern)) {
                $found[$name] = true;
                $results[] = [
                    'value' => $name,
                    'confidence' => 0.9,
                    'evidence' => "Inline script pattern: {$pattern}",
                ];
            }
        }

        // Extract tracking IDs from script URLs and inline scripts
        $allContent = implode("\n", $html->inlineScripts) . "\n" . implode("\n", $html->scripts);
        $trackingIds = $this->extractTrackingIds($allContent);

        if (empty($results) && empty($trackingIds)) {
            return null;
        }

        $output = [];
        if (!empty($results)) {
            $output['tools'] = $results;
        }
        if (!empty($trackingIds)) {
            $output['tracking_ids'] = $trackingIds;
        }

        $tags = array_column($results, 'value');

        return ['marketing' => ['analytics' => $output], '_tags' => $tags];
    }

    /**
     * @return array<string, string>
     */
    private function extractTrackingIds(string $content): array
    {
        $ids = [];

        if (preg_match('/["\']?(G-[A-Z0-9]+)["\']?/', $content, $m)) {
            $ids['ga4'] = $m[1];
        }

        if (preg_match('/["\']?(UA-\d+-\d+)["\']?/', $content, $m)) {
            $ids['universal_analytics'] = $m[1];
        }

        if (preg_match('/["\']?(GTM-[A-Z0-9]+)["\']?/', $content, $m)) {
            $ids['gtm'] = $m[1];
        }

        if (preg_match('/["\']?(GT-[A-Z0-9]+)["\']?/', $content, $m)) {
            $ids['google_tag'] = $m[1];
        }

        if (preg_match('/fbq\s*\(\s*[\'"]init[\'"]\s*,\s*[\'"](\d+)[\'"]/', $content, $m)) {
            $ids['facebook_pixel'] = $m[1];
        }

        return $ids;
    }
}
