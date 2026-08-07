<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class FrameworkDetector extends Detector
{
    private const FRONTEND_SCRIPT_PATTERNS = [
        'React' => '/[\/\/@]react(-dom)?[\/@.\-].*\.js/i',
        'Vue.js' => '/[\/\/@]vue[\/@.\-].*\.js/i',
        'Angular' => '/[\/\/@]angular[\/@.\-].*\.js/i',
        'Svelte' => '/[\/\/@]svelte[\/@.\-]/i',
        'Alpine.js' => '/alpinejs|[\/]alpine(\.min)?\.js/i',
    ];

    private const FRONTEND_INLINE_PATTERNS = [
        'Next.js' => '/__NEXT_DATA__/i',
        'Nuxt.js' => '/__NUXT__|nuxt\.config/i',
        'Gatsby' => '/___gatsby/i',
        'Svelte' => '/__svelte_\w+/i',
    ];

    private const FRONTEND_HTML_PATTERNS = [
        'Angular' => '/ng-version|ng-app/i',
        'Vue.js' => '/data-v-[a-f0-9]/i',
        'React' => '/data-reactroot|__next/i',
        'Livewire' => '/wire:(click|submit|model|init|navigate)\b/i',
    ];

    private const BACKEND_COOKIE_PATTERNS = [
        'Laravel' => '/^(laravel_session|XSRF-TOKEN)$/i',
        'Rails' => '/^_[a-z][a-z0-9_]+_session$/i',
        'Django' => '/^(csrftoken|sessionid)$/i',
        'ASP.NET' => '/^(\.AspNetCore\.|ASP\.NET_SessionId)/i',
        'CakePHP' => '/^CAKEPHP$/i',
        'CodeIgniter' => '/^ci_session$/i',
    ];

    private const BACKEND_HEADER_PATTERNS = [
        'ASP.NET' => 'x-aspnet-version',
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

        $results = [];

        // Frontend: script URLs
        foreach (self::FRONTEND_SCRIPT_PATTERNS as $name => $pattern) {
            $matches = $html->scriptsMatching($pattern);
            if (!empty($matches)) {
                $results[] = [
                    'value' => $name,
                    'type' => 'frontend',
                    'confidence' => 0.85,
                    'evidence' => 'Script src: ' . $matches[0],
                ];
            }
        }

        // Frontend: inline script markers
        foreach (self::FRONTEND_INLINE_PATTERNS as $name => $pattern) {
            if ($html->hasInlineScriptMatching($pattern)) {
                $results[] = [
                    'value' => $name,
                    'type' => 'frontend',
                    'confidence' => 0.9,
                    'evidence' => "Inline script marker: {$pattern}",
                ];
            }
        }

        // Frontend: HTML patterns
        $body = $http?->body ?? '';
        foreach (self::FRONTEND_HTML_PATTERNS as $name => $pattern) {
            if (preg_match($pattern, $body)) {
                // Skip if already found via stronger signal
                if ($this->alreadyDetected($results, $name)) {
                    continue;
                }
                $results[] = [
                    'value' => $name,
                    'type' => 'frontend',
                    'confidence' => 0.7,
                    'evidence' => "HTML pattern: {$pattern}",
                ];
            }
        }

        // Backend: cookies
        if ($http !== null) {
            foreach (self::BACKEND_COOKIE_PATTERNS as $name => $pattern) {
                foreach (array_keys($http->cookies) as $cookieName) {
                    if (preg_match($pattern, $cookieName)) {
                        $results[] = [
                            'value' => $name,
                            'type' => 'backend',
                            'confidence' => 0.8,
                            'evidence' => "Cookie: {$cookieName}",
                        ];
                        break;
                    }
                }
            }

            // Backend: headers
            foreach (self::BACKEND_HEADER_PATTERNS as $name => $header) {
                if ($http->header($header) !== null) {
                    if (!$this->alreadyDetected($results, $name)) {
                        $results[] = [
                            'value' => $name,
                            'type' => 'backend',
                            'confidence' => 0.7,
                            'evidence' => "HTTP header: {$header}",
                        ];
                    }
                }
            }
        }

        if (empty($results)) {
            return null;
        }

        $tags = array_column($results, 'value');

        return ['technology' => ['frameworks' => $results], '_tags' => $tags];
    }

    private function alreadyDetected(array $results, string $name): bool
    {
        foreach ($results as $r) {
            if ($r['value'] === $name) {
                return true;
            }
        }

        return false;
    }
}
