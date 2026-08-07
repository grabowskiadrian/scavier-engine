<?php

namespace Scavier\Collector\Data;

final class RdapData
{
    /**
     * @param array<string> $status Domain status flags
     * @param array<string> $nameservers
     */
    public function __construct(
        public readonly string $domain,
        public readonly ?string $registrar = null,
        public readonly ?string $registrationDate = null,
        public readonly ?string $expirationDate = null,
        public readonly ?string $lastUpdated = null,
        public readonly array $status = [],
        public readonly array $nameservers = [],
    ) {
    }
}
