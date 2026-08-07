<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\Data\HttpData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class DiscoveryCollector extends Collector
{
    private const PATHS = [
        // Standards
        '/robots.txt',
        '/sitemap.xml',
        '/manifest.json',
        '/manifest.webmanifest',
        '/.well-known/security.txt',
        '/favicon.ico',
        '/humans.txt',

        // AI readiness
        '/llms.txt',
        '/.well-known/mcp.json',

        // API discovery
        '/openapi.json',
        '/swagger.json',

        // Ad/monetization
        '/ads.txt',

        // Security exposure (should return 404)
        '/.env',
        '/.git/HEAD',

        // Business pages — contact
        '/contact',
        '/kontakt',
        '/contact-us',

        // Business pages — about
        '/about',
        '/about-us',
        '/o-nas',
        '/o-firmie',

        // Business pages — legal
        '/impressum',
        '/imprint',
        '/privacy-policy',
        '/polityka-prywatnosci',
        '/privacy',
        '/cookie-policy',
        '/polityka-cookies',
        '/terms',
        '/regulamin',

        // Business pages — pricing
        '/pricing',
        '/cennik',
    ];

    /** Keywords to match in footer links for dynamic discovery */
    private const FOOTER_KEYWORDS = [
        'contact', 'kontakt', 'about', 'o-nas', 'o-firmie',
        'privacy', 'prywatno', 'cookie', 'regulamin', 'terms',
        'impressum', 'imprint', 'legal', 'prawne',
        'pricing', 'cennik', 'career', 'kariera', 'praca',
    ];

    private const MAX_CONCURRENT = 10;

    public static function dependencies(): array
    {
        return [HttpCollector::class];
    }

    public function execute(Target $target, Context $context): void
    {
        $baseUrl = $target->scheme() . '://' . $target->host();

        // 1. Fetch hardcoded paths in parallel
        $urls = [];
        foreach (self::PATHS as $path) {
            $urls[$path] = $baseUrl . $path;
        }

        $results = $this->fetchMulti($urls);

        // 2. Discover additional pages from footer links
        $http = $context->get(HttpData::class);

        if ($http !== null) {
            $footerLinks = $this->extractFooterLinks($http->body, $baseUrl);
            $extraUrls = [];

            foreach ($footerLinks as $path) {
                if (!isset($results[$path])) {
                    $extraUrls[$path] = $baseUrl . $path;
                }
            }

            if ($extraUrls !== []) {
                $results = array_merge($results, $this->fetchMulti($extraUrls));
            }
        }

        $context->set(new DiscoveryData($results));
    }

    /**
     * Fetch multiple URLs in parallel using curl_multi.
     *
     * @param array<string, string> $urls path => full URL
     * @return array<string, array{status: int, body: string|null}>
     */
    private function fetchMulti(array $urls): array
    {
        $results = [];
        $chunks = array_chunk($urls, self::MAX_CONCURRENT, true);

        foreach ($chunks as $chunk) {
            $mh = curl_multi_init();
            $handles = [];

            foreach ($chunk as $path => $url) {
                $ch = curl_init();

                curl_setopt_array($ch, [
                    CURLOPT_URL => $url,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_MAXREDIRS => 3,
                    CURLOPT_TIMEOUT => 5,
                    CURLOPT_CONNECTTIMEOUT => 3,
                    CURLOPT_USERAGENT => \Scavier\Engine\Scavier::userAgent(),
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_PROTOCOLS_STR => 'http,https',
                    CURLOPT_REDIR_PROTOCOLS_STR => 'http,https',
                ]);

                curl_multi_add_handle($mh, $ch);
                $handles[$path] = $ch;
            }

            // Execute all requests
            do {
                $status = curl_multi_exec($mh, $active);
                if ($active) {
                    curl_multi_select($mh, 1);
                }
            } while ($active && $status === CURLM_OK);

            // Collect results
            foreach ($handles as $path => $ch) {
                $body = curl_multi_getcontent($ch);
                $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

                if ($body === false || $body === null || $httpCode === 0) {
                    $results[$path] = ['status' => 0, 'body' => null];
                } else {
                    $keepBody = $httpCode >= 200 && $httpCode < 400 && strlen($body) < 512000;
                    $results[$path] = [
                        'status' => $httpCode,
                        'body' => $keepBody ? $body : null,
                    ];
                }

                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
            }

            curl_multi_close($mh);
        }

        return $results;
    }

    /**
     * Extract links from <footer> that match business keywords.
     *
     * @return list<string> Paths like /pl/polityka-prywatnosci
     */
    private function extractFooterLinks(string $html, string $baseUrl): array
    {
        // Find <footer> content
        if (!preg_match('/<footer[^>]*>(.*?)<\/footer>/si', $html, $footerMatch)) {
            return [];
        }

        $footer = $footerMatch[1];
        $paths = [];
        $host = parse_url($baseUrl, PHP_URL_HOST);

        // Extract all hrefs from footer
        if (!preg_match_all('/href=["\']([^"\']+)["\']/', $footer, $matches)) {
            return [];
        }

        foreach ($matches[1] as $href) {
            $href = trim($href);

            // Skip anchors, external links, javascript, mailto, tel
            if (str_starts_with($href, '#') || str_starts_with($href, 'javascript:')
                || str_starts_with($href, 'mailto:') || str_starts_with($href, 'tel:')) {
                continue;
            }

            // Convert to path
            $path = null;

            if (str_starts_with($href, '/')) {
                $path = $href;
            } elseif (str_starts_with($href, 'http')) {
                $parsed = parse_url($href);
                // Only same-domain links
                if (isset($parsed['host']) && $parsed['host'] === $host) {
                    $path = $parsed['path'] ?? '/';
                }
            }

            if ($path === null || $path === '/') {
                continue;
            }

            // Remove trailing slash and query string
            $path = explode('?', $path)[0];
            $path = rtrim($path, '/');

            if ($path === '') {
                continue;
            }

            // Check if path contains any business keyword
            $lowerPath = strtolower($path);
            foreach (self::FOOTER_KEYWORDS as $keyword) {
                if (str_contains($lowerPath, $keyword)) {
                    $paths[] = $path;
                    break;
                }
            }
        }

        return array_values(array_unique($paths));
    }
}
