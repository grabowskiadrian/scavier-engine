<?php

namespace Scavier\Collector\Data;

final class DnsData
{
    /**
     * @param array<array> $a A records
     * @param array<array> $aaaa AAAA records
     * @param array<array> $mx MX records (sorted by priority)
     * @param array<array> $ns NS records
     * @param array<array> $txt TXT records
     * @param array<array> $cname CNAME records
     * @param array<array> $soa SOA records
     * @param array<string, string> $ptr IP => PTR hostname (reverse DNS)
     * @param array<array{flags: int, tag: string, value: string}> $caa CAA records
     * @param array<array{usage: int, selector: int, type: int, data: string}> $tlsa TLSA/DANE records
     */
    public function __construct(
        public readonly string $domain,
        public readonly array $a = [],
        public readonly array $aaaa = [],
        public readonly array $mx = [],
        public readonly array $ns = [],
        public readonly array $txt = [],
        public readonly array $cname = [],
        public readonly array $soa = [],
        public readonly array $ptr = [],
        public readonly array $caa = [],
        public readonly bool $dnssec = false,
        public readonly array $tlsa = [],
    ) {
    }

    /**
     * @return list<string> IP addresses
     */
    public function ips(): array
    {
        $ips = [];

        foreach ($this->a as $record) {
            $ips[] = $record['ip'] ?? '';
        }

        foreach ($this->aaaa as $record) {
            $ips[] = $record['ipv6'] ?? '';
        }

        return array_values(array_filter($ips));
    }

    /**
     * @return list<string> Nameserver hostnames
     */
    public function nameservers(): array
    {
        return array_map(
            fn(array $r) => rtrim($r['target'] ?? '', '.'),
            $this->ns
        );
    }

    /**
     * @return list<string> MX hostnames sorted by priority
     */
    public function mailExchangers(): array
    {
        return array_map(
            fn(array $r) => rtrim($r['target'] ?? '', '.'),
            $this->mx
        );
    }

    /**
     * @return list<string> TXT record values
     */
    public function txtValues(): array
    {
        return array_map(
            fn(array $r) => $r['txt'] ?? '',
            $this->txt
        );
    }

    /**
     * @return list<string> CNAME targets
     */
    public function cnameTargets(): array
    {
        return array_map(
            fn(array $r) => rtrim($r['target'] ?? '', '.'),
            $this->cname
        );
    }

    /**
     * @return list<string> Allowed certificate authorities from CAA records
     */
    public function caaIssuers(): array
    {
        $issuers = [];

        foreach ($this->caa as $record) {
            if (($record['tag'] ?? '') === 'issue' || ($record['tag'] ?? '') === 'issuewild') {
                $value = $record['value'] ?? '';
                if ($value !== '' && $value !== ';') {
                    $issuers[] = explode(';', $value)[0];
                }
            }
        }

        return array_values(array_unique($issuers));
    }

    public function hasCaa(): bool
    {
        return $this->caa !== [];
    }

    public function hasDnssec(): bool
    {
        return $this->dnssec;
    }

    public function hasTlsa(): bool
    {
        return $this->tlsa !== [];
    }
}
