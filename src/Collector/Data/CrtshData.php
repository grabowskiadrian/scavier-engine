<?php

namespace Scavier\Collector\Data;

final class CrtshData
{
    /**
     * @param array<array{commonName: string, nameValue: string, issuerName: string, notBefore: string, notAfter: string, serialNumber: string}> $certificates
     * @param list<string> $subdomains Unique subdomains discovered
     */
    public function __construct(
        public readonly string $domain,
        public readonly array $certificates = [],
        public readonly array $subdomains = [],
    ) {
    }

    /**
     * @return list<string> Subdomains that are not wildcards
     */
    public function concreteSubdomains(): array
    {
        return array_values(array_filter(
            $this->subdomains,
            fn(string $s) => !str_starts_with($s, '*.'),
        ));
    }

    /**
     * @return list<string> Wildcard entries
     */
    public function wildcards(): array
    {
        return array_values(array_filter(
            $this->subdomains,
            fn(string $s) => str_starts_with($s, '*.'),
        ));
    }

    /**
     * @return list<string> Unique issuers (certificate authorities)
     */
    public function issuers(): array
    {
        $issuers = [];

        foreach ($this->certificates as $cert) {
            $issuer = $cert['issuerName'] ?? null;
            if ($issuer !== null && !in_array($issuer, $issuers, true)) {
                $issuers[] = $issuer;
            }
        }

        return $issuers;
    }
}
