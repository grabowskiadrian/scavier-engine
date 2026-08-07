<?php

namespace Scavier\Collector\Data;

final class SubdomainDnsData
{
    /**
     * @param array<string, array{ip: string|null, cname: string|null}> $resolved subdomain => resolution info
     * @param list<string> $failed Subdomains that did not resolve
     */
    public function __construct(
        public readonly string $domain,
        public readonly array $resolved = [],
        public readonly array $failed = [],
    ) {
    }

    /**
     * @return list<string> All resolved subdomain FQDNs
     */
    public function found(): array
    {
        return array_keys($this->resolved);
    }

    public function count(): int
    {
        return count($this->resolved);
    }
}
