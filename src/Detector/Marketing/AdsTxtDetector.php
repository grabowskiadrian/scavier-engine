<?php

namespace Scavier\Detector\Marketing;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class AdsTxtDetector extends Detector
{
    private const KNOWN_EXCHANGES = [
        'google.com' => 'Google',
        'appnexus.com' => 'AppNexus/Xandr',
        'openx.com' => 'OpenX',
        'rubiconproject.com' => 'Rubicon/Magnite',
        'pubmatic.com' => 'PubMatic',
        'indexexchange.com' => 'Index Exchange',
        'smartadserver.com' => 'Smart AdServer',
        'amazon-adsystem.com' => 'Amazon',
        'contextweb.com' => 'PulsePoint',
        'sovrn.com' => 'Sovrn',
        'triplelift.com' => 'TripleLift',
        'criteo.com' => 'Criteo',
        'media.net' => 'Media.net',
        'taboola.com' => 'Taboola',
        'outbrain.com' => 'Outbrain',
    ];

    public static function dependencies(): array
    {
        return [DiscoveryCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $discovery = $context->get(DiscoveryData::class);

        if ($discovery === null || !$discovery->exists('/ads.txt')) {
            return null;
        }

        $body = $discovery->body('/ads.txt');

        if ($body === null) {
            return null;
        }

        // Reject HTML responses (redirect to homepage, error pages, etc.)
        if (preg_match('/<(!DOCTYPE|html|head|body|script|style)/i', $body)) {
            return null;
        }

        $entries = 0;
        $exchanges = [];

        foreach (explode("\n", $body) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $parts = explode(',', $line);

            if (count($parts) >= 3) {
                $domain = strtolower(trim($parts[0]));

                // Validate domain format (must look like a domain, not HTML fragments)
                if (!preg_match('/^[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}$/', $domain)) {
                    continue;
                }

                $entries++;
                $name = self::KNOWN_EXCHANGES[$domain] ?? $domain;

                if (!isset($exchanges[$name])) {
                    $exchanges[$name] = 0;
                }
                $exchanges[$name]++;
            }
        }

        if ($entries === 0) {
            return null;
        }

        $exchangeNames = array_keys($exchanges);

        return [
            'marketing' => [
                'ads_txt' => [
                    'exists' => true,
                    'entries' => $entries,
                    'exchanges' => $exchangeNames,
                    'exchange_count' => count($exchanges),
                    'confidence' => 1.0,
                    'evidence' => 'ads.txt found and parsed',
                ],
            ],
            '_tags' => ['AdsTxt'],
        ];
    }
}
