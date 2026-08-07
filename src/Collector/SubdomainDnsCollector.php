<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\SubdomainDnsData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class SubdomainDnsCollector extends Collector
{
    private const PREFIXES = [
        // Most common & high-value (covers ~95% of real subdomains)
        'www', 'mail', 'webmail', 'smtp', 'imap',
        'app', 'api', 'cdn', 'static', 'media',
        'admin', 'panel', 'cpanel',
        'dev', 'staging', 'test', 'beta',
        'shop', 'store', 'blog',
        'ftp', 'vpn', 'ns1', 'ns2',
        'auth', 'login', 'sso',
        'docs', 'help', 'status', 'support',
        'git', 'ci', 'monitoring',
        'autodiscover', 'remote', 'intranet',
    ];

    public function execute(Target $target, Context $context): void
    {
        $host = $target->host();

        if ($host === null) {
            return;
        }

        $domain = $this->extractRegistrableDomain($host);
        $resolved = [];
        $failed = [];

        foreach (self::PREFIXES as $prefix) {
            $subdomain = "{$prefix}.{$domain}";

            $result = $this->resolve($subdomain);

            if ($result !== null) {
                $resolved[$subdomain] = $result;
            } else {
                $failed[] = $subdomain;
            }
        }

        if ($resolved === []) {
            return;
        }

        $context->set(new SubdomainDnsData(
            domain: $domain,
            resolved: $resolved,
            failed: $failed,
        ));
    }

    /**
     * @return array{ip: string|null, cname: string|null}|null
     */
    private function resolve(string $subdomain): ?array
    {
        // Try A record first
        $a = @dns_get_record($subdomain, DNS_A);

        if ($a !== false && $a !== []) {
            return [
                'ip' => $a[0]['ip'] ?? null,
                'cname' => null,
            ];
        }

        // Try CNAME
        $cname = @dns_get_record($subdomain, DNS_CNAME);

        if ($cname !== false && $cname !== []) {
            return [
                'ip' => null,
                'cname' => rtrim($cname[0]['target'] ?? '', '.'),
            ];
        }

        return null;
    }

    private function extractRegistrableDomain(string $host): string
    {
        $parts = explode('.', $host);
        $twoPartTlds = ['co.uk', 'com.br', 'com.au', 'co.jp', 'co.kr', 'com.pl', 'org.uk', 'net.au'];

        if (count($parts) >= 3) {
            $lastTwo = implode('.', array_slice($parts, -2));
            if (in_array($lastTwo, $twoPartTlds, true)) {
                return implode('.', array_slice($parts, -3));
            }
        }

        return implode('.', array_slice($parts, -2));
    }
}
