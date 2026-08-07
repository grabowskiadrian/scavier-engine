<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\CrtshCollector;
use Scavier\Collector\Data\CrtshData;
use Scavier\Collector\Data\SubdomainDnsData;
use Scavier\Collector\Data\TlsData;
use Scavier\Collector\SubdomainDnsCollector;
use Scavier\Collector\TlsCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class SubdomainDetector extends Detector
{
    private const SERVICE_PATTERNS = [
        'mail' => '/^(mail|smtp|imap|pop|webmail|mx)\./i',
        'app' => '/^(app|dashboard|portal|my|account)\./i',
        'api' => '/^(api|rest|graphql|ws)\./i',
        'cdn' => '/^(cdn|static|assets|media|img|images)\./i',
        'dev' => '/^(dev|staging|stage|test|qa|uat|preview|sandbox)\./i',
        'docs' => '/^(docs|doc|documentation|help|support|wiki|kb)\./i',
        'admin' => '/^(admin|manage|cms|panel|backend|cpanel)\./i',
        'shop' => '/^(shop|store|checkout|cart)\./i',
        'blog' => '/^(blog|news|articles)\./i',
        'auth' => '/^(auth|login|sso|id|identity|accounts)\./i',
        'monitoring' => '/^(monitoring|grafana|prometheus|status)\./i',
        'ci' => '/^(ci|jenkins|gitlab|git)\./i',
        'database' => '/^(db|database|mysql|postgres|redis|mongo)\./i',
        'vpn' => '/^(vpn|remote|intranet)\./i',
    ];

    public static function dependencies(): array
    {
        return [TlsCollector::class, CrtshCollector::class, SubdomainDnsCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $collected = [];

        // Source 1: TLS SAN (highest confidence)
        $tls = $context->get(TlsData::class);
        if ($tls !== null) {
            foreach ($tls->san as $name) {
                if (!str_starts_with($name, '*.')) {
                    $collected[$name] = ['source' => 'tls_san', 'confidence' => 1.0];
                }
            }
        }

        // Source 2: Certificate Transparency (crt.sh)
        $crtsh = $context->get(CrtshData::class);
        if ($crtsh !== null) {
            foreach ($crtsh->concreteSubdomains() as $name) {
                if (!isset($collected[$name])) {
                    $collected[$name] = ['source' => 'certificate_transparency', 'confidence' => 0.95];
                }
            }
        }

        // Source 3: DNS brute force
        $dnsbrute = $context->get(SubdomainDnsData::class);
        if ($dnsbrute !== null) {
            foreach ($dnsbrute->found() as $name) {
                if (!isset($collected[$name])) {
                    $collected[$name] = ['source' => 'dns_brute', 'confidence' => 1.0];
                }
            }
        }

        if (count($collected) <= 1) {
            return null;
        }

        $subdomains = [];
        foreach ($collected as $name => $info) {
            $service = null;
            foreach (self::SERVICE_PATTERNS as $type => $pattern) {
                if (preg_match($pattern, $name)) {
                    $service = $type;
                    break;
                }
            }

            $entry = [
                'name' => $name,
                'service' => $service,
                'source' => $info['source'],
            ];

            // Add resolution info from DNS brute if available
            if ($dnsbrute !== null && isset($dnsbrute->resolved[$name])) {
                $res = $dnsbrute->resolved[$name];
                if ($res['ip'] !== null) {
                    $entry['ip'] = $res['ip'];
                }
                if ($res['cname'] !== null) {
                    $entry['cname'] = $res['cname'];
                }
            }

            $subdomains[] = $entry;
        }

        // Sort by name
        usort($subdomains, fn($a, $b) => strcmp($a['name'], $b['name']));

        $sources = array_unique(array_column($subdomains, 'source'));

        return [
            'infrastructure' => [
                'subdomains' => [
                    'count' => count($subdomains),
                    'domains' => $subdomains,
                    'sources' => array_values($sources),
                    'confidence' => 1.0,
                    'evidence' => 'Combined: ' . implode(', ', $sources),
                ],
            ]
        ];
    }
}
