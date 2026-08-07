<?php

namespace Scavier\Collector\Data;

final class WhoisData
{
    /**
     * @param array<string, string> $networks IP => network info (netname, org, etc.)
     */
    public function __construct(
        public readonly ?int $asn = null,
        public readonly ?string $asnName = null,
        public readonly ?string $netName = null,
        public readonly ?string $netRange = null,
        public readonly ?string $organization = null,
        public readonly ?string $country = null,
        public readonly ?string $abuseContact = null,
        public readonly ?string $rawOutput = null,
    ) {
    }
}
