<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\DnsCollector;
use Scavier\Collector\HttpCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class CdnDetector extends Detector
{
    private const HEADER_SIGNALS = [
        'Cloudflare' => ['cf-ray', 'cf-cache-status'],
        'Fastly' => ['x-served-by', 'x-cache', 'x-fastly-request-id'],
        'AWS CloudFront' => ['x-amz-cf-id', 'x-amz-cf-pop'],
        'Akamai' => ['x-akamai-transformed'],
        'Sucuri' => ['x-sucuri-id'],
        'KeyCDN' => ['x-edge-location'],
        'Bunny CDN' => ['cdn-pullzone', 'cdn-uid'],
    ];

    private const SERVER_SIGNALS = [
        'Cloudflare' => '/^cloudflare$/i',
        'AWS CloudFront' => '/^CloudFront$/i',
        'Netlify' => '/^Netlify$/i',
        'Vercel' => '/^Vercel$/i',
    ];

    private const CNAME_SIGNALS = [
        'Cloudflare' => '/\.cdn\.cloudflare\.net$/i',
        'AWS CloudFront' => '/\.cloudfront\.net$/i',
        'Fastly' => '/\.fastly\.net$/i',
        'Akamai' => '/\.akamaiedge\.net$|\.akamai\.net$/i',
        'Azure CDN' => '/\.azureedge\.net$/i',
        'Google Cloud CDN' => '/\.googleusercontent\.com$/i',
        'Netlify' => '/\.netlify\.app$/i',
        'Vercel' => '/\.vercel-dns\.com$/i',
    ];

    public static function dependencies(): array
    {
        return [HttpCollector::class, DnsCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $http = $context->get(HttpData::class);
        $dns = $context->get(DnsData::class);

        $signals = [];

        // Check HTTP headers
        if ($http !== null) {
            foreach (self::HEADER_SIGNALS as $cdn => $headers) {
                foreach ($headers as $header) {
                    $value = $http->header($header);
                    if ($value !== null) {
                        $signals[$cdn][] = ['confidence' => 0.95, 'evidence' => "HTTP header: {$header}: {$value}"];
                        break;
                    }
                }
            }

            // Check Server header
            $server = $http->header('server');
            if ($server !== null) {
                foreach (self::SERVER_SIGNALS as $cdn => $pattern) {
                    if (preg_match($pattern, $server) && !isset($signals[$cdn])) {
                        $signals[$cdn][] = ['confidence' => 0.9, 'evidence' => "Server header: {$server}"];
                    }
                }
            }
        }

        // Check CNAME records
        if ($dns !== null) {
            foreach ($dns->cnameTargets() as $cname) {
                foreach (self::CNAME_SIGNALS as $cdn => $pattern) {
                    if (preg_match($pattern, $cname) && !isset($signals[$cdn])) {
                        $signals[$cdn][] = ['confidence' => 0.9, 'evidence' => "CNAME: {$cname}"];
                    }
                }
            }
        }

        if (empty($signals)) {
            return null;
        }

        // Pick the CDN with the most/strongest signals
        $best = null;
        $bestConfidence = 0;
        $bestEvidence = [];

        foreach ($signals as $cdn => $evidences) {
            $confidence = min(1.0, max(array_column($evidences, 'confidence')) + (count($evidences) - 1) * 0.03);
            if ($confidence > $bestConfidence) {
                $best = $cdn;
                $bestConfidence = $confidence;
                $bestEvidence = array_column($evidences, 'evidence');
            }
        }

        return [
            'infrastructure' => [
                'cdn' => [
                    'value' => $best,
                    'confidence' => round($bestConfidence, 2),
                    'evidence' => implode('; ', $bestEvidence),
                ],
            ],
            '_tags' => [$best],
        ];
    }
}
