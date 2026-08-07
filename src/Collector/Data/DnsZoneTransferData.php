<?php

namespace Scavier\Collector\Data;

final class DnsZoneTransferData
{
    /**
     * @param array<string, array<array{type: string, value: string}>> $records NS => records found
     * @param list<string> $vulnerableNameservers Nameservers that allow AXFR
     */
    public function __construct(
        public readonly string $domain,
        public readonly bool $vulnerable = false,
        public readonly array $vulnerableNameservers = [],
        public readonly array $records = [],
    ) {
    }

    /**
     * @return list<string> All unique hostnames discovered via zone transfer
     */
    public function discoveredHostnames(): array
    {
        $hostnames = [];

        foreach ($this->records as $nsRecords) {
            foreach ($nsRecords as $record) {
                $value = $record['value'] ?? '';
                if ($value !== '' && !in_array($value, $hostnames, true)) {
                    $hostnames[] = $value;
                }
            }
        }

        return $hostnames;
    }
}
