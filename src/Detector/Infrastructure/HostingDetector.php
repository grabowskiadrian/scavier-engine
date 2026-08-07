<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\Data\WhoisData;
use Scavier\Collector\DnsCollector;
use Scavier\Collector\HttpCollector;
use Scavier\Collector\WhoisCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class HostingDetector extends Detector
{
    private const HEADER_SIGNALS = [
        'Netlify' => '/^Netlify$/i',
        'Vercel' => '/^Vercel$/i',
        'GitHub Pages' => '/^GitHub\.com$/i',
        'Heroku' => '/^gunicorn|cowboy/i',
    ];

    private const EXTRA_HEADER_SIGNALS = [
        'Kinsta' => 'x-kinsta-cache',
        'WP Engine' => 'x-powered-by', // checked for "WP Engine" value
        'Pantheon' => 'x-pantheon-styx-hostname',
        'Flywheel' => 'x-fw-hash',
        'Cloudways' => 'x-turbo-charged-by',
    ];

    private const CNAME_PATTERNS = [
        'AWS' => '/\.amazonaws\.com$|\.aws\./i',
        'Google Cloud' => '/\.googleusercontent\.com$|\.google\.com$/i',
        'Azure' => '/\.azurewebsites\.net$|\.azure\./i',
        'Netlify' => '/\.netlify\.(app|com)$/i',
        'Vercel' => '/\.vercel\.app$|\.vercel-dns\.com$/i',
        'GitHub Pages' => '/\.github\.io$/i',
        'Heroku' => '/\.herokuapp\.com$/i',
        'Fly.io' => '/\.fly\.dev$/i',
        'Railway' => '/\.railway\.app$/i',
        'Render' => '/\.onrender\.com$/i',
    ];

    // IP ranges are supplementary to ASN detection. Last updated: Aug 2026.
    // ASN_PATTERNS (via WhoisCollector) is the preferred method — more stable.
    private const IP_PATTERNS = [
        'Cloudflare' => [
            '104.16.0.0/12', '172.64.0.0/13', '131.0.72.0/22',
            '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20',
            '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
        ],
        'Hetzner' => ['136.243.0.0/16', '138.201.0.0/16', '148.251.0.0/16', '176.9.0.0/16', '178.63.0.0/16', '88.198.0.0/16', '95.216.0.0/16', '65.108.0.0/16', '65.109.0.0/16'],
        'OVH' => ['51.68.0.0/16', '51.75.0.0/16', '51.77.0.0/16', '51.79.0.0/16', '51.83.0.0/16', '51.89.0.0/16', '51.91.0.0/16', '54.36.0.0/16', '54.37.0.0/16', '54.38.0.0/16'],
        'DigitalOcean' => ['64.225.0.0/16', '134.122.0.0/16', '143.198.0.0/16', '157.245.0.0/16', '159.65.0.0/16', '159.89.0.0/16', '161.35.0.0/16', '164.90.0.0/16', '164.92.0.0/16', '167.71.0.0/16', '167.172.0.0/16', '174.138.0.0/16', '178.128.0.0/16', '188.166.0.0/16', '206.189.0.0/16', '209.97.0.0/16'],
    ];

    private const ASN_PATTERNS = [
        'Cloudflare' => '/cloudflare/i',
        'AWS' => '/amazon|aws/i',
        'Google Cloud' => '/google/i',
        'Azure' => '/microsoft/i',
        'Hetzner' => '/hetzner/i',
        'OVH' => '/\bovh\b/i',
        'DigitalOcean' => '/digitalocean/i',
        'Linode/Akamai' => '/linode|akamai/i',
        'Vultr' => '/vultr/i',
        'Scaleway' => '/scaleway|online\.net/i',
        'Contabo' => '/contabo/i',
        'Oracle Cloud' => '/oracle/i',
        'Alibaba Cloud' => '/alibaba|aliyun/i',
        'Leaseweb' => '/leaseweb/i',
        'GoDaddy' => '/godaddy|secureserver/i',
        'Hostinger' => '/hostinger/i',
        'IONOS' => '/ionos|1\&1/i',
    ];

    public static function dependencies(): array
    {
        return [HttpCollector::class, DnsCollector::class, WhoisCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $http = $context->get(HttpData::class);
        $dns = $context->get(DnsData::class);

        $candidates = [];

        // Check Server header
        if ($http !== null) {
            $server = $http->header('server');
            if ($server !== null) {
                foreach (self::HEADER_SIGNALS as $host => $pattern) {
                    if (preg_match($pattern, $server)) {
                        $candidates[] = ['host' => $host, 'confidence' => 0.9, 'evidence' => "Server header: {$server}"];
                    }
                }
            }

            // Check hosting-specific headers
            foreach (self::EXTRA_HEADER_SIGNALS as $host => $header) {
                $value = $http->header($header);
                if ($value !== null) {
                    if ($host === 'WP Engine' && !str_contains(strtolower($value), 'wp engine')) {
                        continue;
                    }
                    $candidates[] = ['host' => $host, 'confidence' => 0.95, 'evidence' => "HTTP header {$header}: {$value}"];
                }
            }
        }

        // Check CNAME records
        if ($dns !== null) {
            foreach ($dns->cnameTargets() as $cname) {
                foreach (self::CNAME_PATTERNS as $host => $pattern) {
                    if (preg_match($pattern, $cname)) {
                        $candidates[] = ['host' => $host, 'confidence' => 0.85, 'evidence' => "CNAME: {$cname}"];
                    }
                }
            }

            // Check IP ranges (A records)
            foreach ($dns->ips() as $ip) {
                foreach (self::IP_PATTERNS as $host => $ranges) {
                    foreach ($ranges as $cidr) {
                        if ($this->ipInCidr($ip, $cidr)) {
                            $candidates[] = ['host' => $host, 'confidence' => 0.7, 'evidence' => "IP {$ip} in {$host} range ({$cidr})"];
                            break;
                        }
                    }
                }
            }

            // PTR records
            $ptrPatterns = [
                'Hetzner' => '/hetzner/i',
                'OVH' => '/ovh\.|kimsufi\.|sys\./i',
                'AWS' => '/\.amazonaws\.com$/i',
                'Google Cloud' => '/\.googleusercontent\.com$/i',
                'DigitalOcean' => '/\.digitalocean\.com$/i',
                'Linode/Akamai' => '/\.linode\.com$/i',
                'Vultr' => '/\.vultr\.com$/i',
            ];

            foreach ($dns->ptr as $ip => $hostname) {
                foreach ($ptrPatterns as $host => $pattern) {
                    if (preg_match($pattern, $hostname)) {
                        $candidates[] = ['host' => $host, 'confidence' => 0.75, 'evidence' => "PTR: {$hostname}"];
                    }
                }
            }
        }

        // Check ASN/organization from IP WHOIS
        $whois = $context->get(WhoisData::class);
        if ($whois !== null) {
            $searchFields = array_filter([$whois->organization, $whois->asnName, $whois->netName]);

            foreach ($searchFields as $field) {
                foreach (self::ASN_PATTERNS as $host => $pattern) {
                    if (preg_match($pattern, $field)) {
                        $evidence = "WHOIS: {$field}";
                        if ($whois->asn !== null) {
                            $evidence .= " (AS{$whois->asn})";
                        }
                        $candidates[] = ['host' => $host, 'confidence' => 0.8, 'evidence' => $evidence];
                        break;
                    }
                }
            }
        }

        if (empty($candidates)) {
            return null;
        }

        // Pick best candidate; if hosting-specific header matches, it wins over generic Server header
        usort($candidates, fn($a, $b) => $b['confidence'] <=> $a['confidence']);
        $best = $candidates[0];

        return $this->result($best['host'], $best['confidence'], $best['evidence']);
    }

    private function result(string $provider, float $confidence, string $evidence): array
    {
        return [
            'infrastructure' => [
                'hosting' => [
                    'value' => $provider,
                    'confidence' => $confidence,
                    'evidence' => $evidence,
                ],
            ],
            '_tags' => [$provider],
        ];
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/') || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        [$subnet, $mask] = explode('/', $cidr);

        return (ip2long($ip) & ~((1 << (32 - (int) $mask)) - 1)) === (ip2long($subnet) & ~((1 << (32 - (int) $mask)) - 1));
    }
}
