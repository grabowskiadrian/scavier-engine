<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\CrtshData;

final class CrtshDataTest extends TestCase
{
    private function sampleData(): CrtshData
    {
        return new CrtshData(
            domain: 'example.com',
            certificates: [
                [
                    'commonName' => 'example.com',
                    'nameValue' => "example.com\nwww.example.com",
                    'issuerName' => "Let's Encrypt",
                    'notBefore' => '2024-01-01',
                    'notAfter' => '2024-04-01',
                    'serialNumber' => 'ABC123',
                ],
                [
                    'commonName' => '*.example.com',
                    'nameValue' => '*.example.com',
                    'issuerName' => 'DigiCert',
                    'notBefore' => '2024-01-01',
                    'notAfter' => '2025-01-01',
                    'serialNumber' => 'DEF456',
                ],
            ],
            subdomains: ['*.example.com', 'www.example.com', 'api.example.com', 'mail.example.com'],
        );
    }

    public function testConcreteSubdomains(): void
    {
        $data = $this->sampleData();
        $concrete = $data->concreteSubdomains();

        $this->assertContains('www.example.com', $concrete);
        $this->assertContains('api.example.com', $concrete);
        $this->assertNotContains('*.example.com', $concrete);
    }

    public function testWildcards(): void
    {
        $data = $this->sampleData();
        $wildcards = $data->wildcards();

        $this->assertSame(['*.example.com'], $wildcards);
    }

    public function testIssuers(): void
    {
        $data = $this->sampleData();
        $issuers = $data->issuers();

        $this->assertContains("Let's Encrypt", $issuers);
        $this->assertContains('DigiCert', $issuers);
        $this->assertCount(2, $issuers);
    }

    public function testEmptyData(): void
    {
        $data = new CrtshData(domain: 'example.com');

        $this->assertSame([], $data->concreteSubdomains());
        $this->assertSame([], $data->wildcards());
        $this->assertSame([], $data->issuers());
    }
}
