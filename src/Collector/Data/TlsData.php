<?php

namespace Scavier\Collector\Data;

final class TlsData
{
    /**
     * @param array<string> $san Subject Alternative Names
     * @param array<string> $supportedProtocols Supported TLS versions (e.g. TLSv1.2, TLSv1.3)
     * @param array<string> $certificateChain Issuer names in the chain
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $subject,
        public readonly array $san,
        public readonly string $validFrom,
        public readonly string $validTo,
        public readonly int $daysUntilExpiry,
        public readonly string $protocol,
        public readonly string $cipher,
        public readonly ?string $serialNumber = null,
        public readonly bool $ocspStapling = false,
        public readonly array $supportedProtocols = [],
        public readonly array $certificateChain = [],
    ) {
    }
}
