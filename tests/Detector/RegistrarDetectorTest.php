<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DomainWhoisData;
use Scavier\Collector\Data\RdapData;
use Scavier\Detector\Infrastructure\RegistrarDetector;
use Scavier\Engine\Context;

final class RegistrarDetectorTest extends TestCase
{
    public function testDetectsRegistrar(): void
    {
        $context = new Context();
        $context->set(new RdapData(
            domain: 'example.com',
            registrar: 'GoDaddy Inc.',
            registrationDate: '2020-01-15',
            expirationDate: '2026-01-15',
            lastUpdated: '2025-06-01',
            status: ['clientTransferProhibited'],
        ));

        $result = (new RegistrarDetector())->detect($context);

        $this->assertSame('example.com', $result['domain']['registration']['domain']);
        $this->assertSame('GoDaddy Inc.', $result['domain']['registration']['registrar']);
        $this->assertSame('2020-01-15', $result['domain']['registration']['registered']);
        $this->assertSame('2026-01-15', $result['domain']['registration']['expires']);
        $this->assertContains('clientTransferProhibited', $result['domain']['registration']['status']);
    }

    public function testHandlesMinimalData(): void
    {
        $context = new Context();
        $context->set(new RdapData(domain: 'example.com'));

        $result = (new RegistrarDetector())->detect($context);

        $this->assertSame('example.com', $result['domain']['registration']['domain']);
        $this->assertArrayNotHasKey('registrar', $result['domain']['registration']);
    }

    public function testReturnsNullWithoutAnyData(): void
    {
        $this->assertNull((new RegistrarDetector())->detect(new Context()));
    }

    public function testEnrichesWithWhoisData(): void
    {
        $context = new Context();
        $context->set(new RdapData(
            domain: 'example.pl',
            registrar: 'OVH SAS',
            registrationDate: '2015-03-10',
        ));
        $context->set(new DomainWhoisData(
            domain: 'example.pl',
            registrant: 'Jan Kowalski',
            registrantOrganization: 'Firma Sp. z o.o.',
            registrar: 'OVH SAS',
            creationDate: '2015-03-10',
            registrantCountry: 'PL',
            registrantEmail: 'admin@example.pl',
            dnssecStatus: 'signedDelegation',
        ));

        $result = (new RegistrarDetector())->detect($context);

        $this->assertSame('Jan Kowalski', $result['domain']['registration']['registrant']);
        $this->assertSame('Firma Sp. z o.o.', $result['domain']['registration']['registrant_organization']);
        $this->assertSame('PL', $result['domain']['registration']['registrant_country']);
        $this->assertSame('admin@example.pl', $result['domain']['registration']['registrant_email']);
        $this->assertSame('signedDelegation', $result['domain']['registration']['dnssec']);
        $this->assertStringContainsString('RDAP', $result['domain']['registration']['evidence']);
        $this->assertStringContainsString('WHOIS', $result['domain']['registration']['evidence']);
    }

    public function testWhoisOnlyWhenRdapUnavailable(): void
    {
        $context = new Context();
        $context->set(new DomainWhoisData(
            domain: 'example.pl',
            registrar: 'nazwa.pl sp. z o.o.',
            creationDate: '2010-05-01',
            expirationDate: '2025-05-01',
            registrantOrganization: 'Firma ABC',
        ));

        $result = (new RegistrarDetector())->detect($context);

        $this->assertSame('example.pl', $result['domain']['registration']['domain']);
        $this->assertSame('nazwa.pl sp. z o.o.', $result['domain']['registration']['registrar']);
        $this->assertSame('2010-05-01', $result['domain']['registration']['registered']);
        $this->assertSame('Firma ABC', $result['domain']['registration']['registrant_organization']);
        $this->assertStringContainsString('WHOIS', $result['domain']['registration']['evidence']);
    }
}
