<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\DnsCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class DnsProviderDetector extends Detector
{
    private const PATTERNS = [
        'Cloudflare' => '/cloudflare\.com$/i',
        'AWS Route 53' => '/awsdns-.*\.com$|awsdns-.*\.net$|awsdns-.*\.org$|awsdns-.*\.co\.uk$/i',
        'Google Cloud DNS' => '/ns-cloud-.*\.googledomains\.com$/i',
        'Google Domains' => '/googledomains\.com$/i',
        'Azure DNS' => '/azure-dns\./i',
        'DigitalOcean' => '/digitalocean\.com$/i',
        'Hetzner' => '/hetzner\.(com|de)$/i',
        'OVH' => '/ovh\.(net|com)$/i',
        'GoDaddy' => '/domaincontrol\.com$/i',
        'Namecheap' => '/registrar-servers\.com$/i',
        'NS1' => '/nsone\.net$/i',
        'DNSimple' => '/dnsimple\.com$/i',
        'ClouDNS' => '/cloudns\.(net|com)$/i',
        'Linode/Akamai' => '/linode\.com$/i',
        'Vercel' => '/vercel-dns\.com$/i',
        'Netlify' => '/netlify\.com$/i',
    ];

    public static function dependencies(): array
    {
        return [DnsCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $dns = $context->get(DnsData::class);

        if ($dns === null || empty($dns->ns)) {
            return null;
        }

        $nameservers = $dns->nameservers();

        foreach (self::PATTERNS as $provider => $pattern) {
            foreach ($nameservers as $ns) {
                if (preg_match($pattern, $ns)) {
                    return [
                        'infrastructure' => [
                            'dns' => [
                                'value' => $provider,
                                'nameservers' => $nameservers,
                                'confidence' => 0.95,
                                'evidence' => "NS record: {$ns}",
                            ],
                        ],
                        '_tags' => [$provider],
                    ];
                }
            }
        }

        return [
            'infrastructure' => [
                'dns' => [
                    'value' => 'Unknown',
                    'nameservers' => $nameservers,
                    'confidence' => 0.5,
                    'evidence' => 'NS: ' . implode(', ', $nameservers),
                ],
            ]
        ];
    }
}
