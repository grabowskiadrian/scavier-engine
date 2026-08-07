<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class CmsDetector extends Detector
{
    private const GENERATORS = [
        'WordPress' => '/wordpress/i',
        'Joomla' => '/joomla/i',
        'Drupal' => '/drupal/i',
        'TYPO3' => '/typo3/i',
        'Hugo' => '/hugo/i',
        'Jekyll' => '/jekyll/i',
        'Ghost' => '/ghost/i',
        'Wix' => '/wix\.com/i',
        'Squarespace' => '/squarespace/i',
        'Webflow' => '/webflow/i',
    ];

    private const HTML_SIGNALS = [
        'WordPress' => ['/\/wp-content\//i', '/\/wp-includes\//i', '/wp-json/i'],
        'Drupal' => ['/\/sites\/default\/files/i', '/Drupal\.settings/i'],
        'Joomla' => ['/\/media\/jui\//i', '/\/components\/com_/i'],
        'Wix' => ['/static\.wixstatic\.com/i', '/wix-code-sdk/i'],
        'Squarespace' => ['/static\.squarespace\.com/i', '/squarespace-cdn\.com/i'],
        'Webflow' => ['/assets\.website-files\.com/i', '/webflow\.js/i'],
    ];

    private const HEADER_SIGNALS = [
        'Drupal' => 'x-drupal-cache',
    ];

    private const COOKIE_SIGNALS = [
        'WordPress' => '/^wordpress_(logged_in|sec|test_cookie)/i',
        'Drupal' => '/^SSESS/i',
    ];

    public static function dependencies(): array
    {
        return [HtmlCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $html = $context->get(HtmlData::class);
        $http = $context->get(HttpData::class);

        if ($html === null) {
            return null;
        }

        $signals = [];

        // Check meta generator
        $generator = $html->metaTag('generator');
        if ($generator !== null) {
            foreach (self::GENERATORS as $cms => $pattern) {
                if (preg_match($pattern, $generator)) {
                    $signals[$cms][] = ['confidence' => 0.95, 'evidence' => "meta generator: {$generator}"];
                }
            }
        }

        // Check HTML body for known patterns
        $body = $http?->body ?? '';
        foreach (self::HTML_SIGNALS as $cms => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $body)) {
                    $signals[$cms][] = ['confidence' => 0.7, 'evidence' => "HTML pattern: {$pattern}"];
                    break;
                }
            }
        }

        // Check headers
        if ($http !== null) {
            foreach (self::HEADER_SIGNALS as $cms => $header) {
                if ($http->header($header) !== null) {
                    $signals[$cms][] = ['confidence' => 0.9, 'evidence' => "HTTP header: {$header}"];
                }
            }

            // Check cookies
            foreach (self::COOKIE_SIGNALS as $cms => $pattern) {
                foreach (array_keys($http->cookies) as $cookieName) {
                    if (preg_match($pattern, $cookieName)) {
                        $signals[$cms][] = ['confidence' => 0.8, 'evidence' => "Cookie: {$cookieName}"];
                        break;
                    }
                }
            }
        }

        if (empty($signals)) {
            return null;
        }

        // Pick CMS with highest aggregate confidence
        $best = null;
        $bestConfidence = 0;
        $bestEvidence = [];

        foreach ($signals as $cms => $evidences) {
            $maxConf = max(array_column($evidences, 'confidence'));
            $confidence = min(1.0, $maxConf + (count($evidences) - 1) * 0.02);
            if ($confidence > $bestConfidence) {
                $best = $cms;
                $bestConfidence = $confidence;
                $bestEvidence = array_column($evidences, 'evidence');
            }
        }

        // Extract version from generator — anchored to detected CMS name
        $version = null;
        if ($generator !== null && $best !== null) {
            $escaped = preg_quote($best, '/');
            if (preg_match('/' . $escaped . '[\s\/]+([\d]+(?:\.[\d]+)*)/i', $generator, $vm)) {
                $version = $vm[1];
            }
        }

        // WordPress-specific: extract plugins and theme
        $wpPlugins = [];
        $wpTheme = null;
        if ($best === 'WordPress' && $html !== null) {
            $allSources = array_merge($html->scripts, $html->stylesheets);
            foreach ($allSources as $src) {
                if (preg_match('/\/wp-content\/plugins\/([^\/]+)\//i', $src, $pm)) {
                    $wpPlugins[$pm[1]] = true;
                }
                if ($wpTheme === null && preg_match('/\/wp-content\/themes\/([^\/]+)\//i', $src, $tm)) {
                    $wpTheme = $tm[1];
                }
            }
        }

        $cmsResult = [
            'value' => $best,
            'confidence' => round($bestConfidence, 2),
            'evidence' => implode('; ', $bestEvidence),
        ];

        if ($version !== null) {
            $cmsResult['version'] = $version;
        }

        if (!empty($wpPlugins)) {
            $cmsResult['plugins'] = array_keys($wpPlugins);
        }

        if ($wpTheme !== null) {
            $cmsResult['theme'] = $wpTheme;
        }

        return [
            'technology' => [
                'cms' => $cmsResult,
            ],
            '_tags' => [$best],
        ];
    }
}
