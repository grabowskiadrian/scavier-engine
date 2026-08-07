<?php

namespace Scavier\Collector\Data;

final class DomainWhoisData
{
    public function __construct(
        public readonly string $domain,
        public readonly ?string $registrant = null,
        public readonly ?string $registrantOrganization = null,
        public readonly ?string $registrar = null,
        public readonly ?string $creationDate = null,
        public readonly ?string $expirationDate = null,
        public readonly ?string $updatedDate = null,
        public readonly ?string $registrantCountry = null,
        public readonly ?string $registrantEmail = null,
        public readonly ?string $dnssecStatus = null,
        public readonly ?string $rawOutput = null,
    ) {
    }
}
