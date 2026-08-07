<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DomainWhoisData;

final class DomainWhoisDataTest extends TestCase
{
    public function testStoresAllFields(): void
    {
        $data = new DomainWhoisData(
            domain: 'example.pl',
            registrant: 'Jan Kowalski',
            registrantOrganization: 'Firma Sp. z o.o.',
            registrar: 'OVH SAS',
            creationDate: '2010-05-15',
            expirationDate: '2025-05-15',
            updatedDate: '2024-01-10',
            registrantCountry: 'PL',
            registrantEmail: 'admin@example.pl',
            dnssecStatus: 'signedDelegation',
        );

        $this->assertSame('example.pl', $data->domain);
        $this->assertSame('Jan Kowalski', $data->registrant);
        $this->assertSame('Firma Sp. z o.o.', $data->registrantOrganization);
        $this->assertSame('OVH SAS', $data->registrar);
        $this->assertSame('2010-05-15', $data->creationDate);
        $this->assertSame('2025-05-15', $data->expirationDate);
        $this->assertSame('PL', $data->registrantCountry);
        $this->assertSame('admin@example.pl', $data->registrantEmail);
        $this->assertSame('signedDelegation', $data->dnssecStatus);
    }

    public function testDefaultsToNull(): void
    {
        $data = new DomainWhoisData(domain: 'example.com');

        $this->assertNull($data->registrant);
        $this->assertNull($data->registrar);
        $this->assertNull($data->creationDate);
        $this->assertNull($data->registrantEmail);
        $this->assertNull($data->dnssecStatus);
    }
}
