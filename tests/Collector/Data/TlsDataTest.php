<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\TlsData;

final class TlsDataTest extends TestCase
{
    public function testNewFields(): void
    {
        $data = new TlsData(
            issuer: "Let's Encrypt",
            subject: 'example.com',
            san: ['example.com', 'www.example.com'],
            validFrom: '2024-01-01',
            validTo: '2024-04-01',
            daysUntilExpiry: 90,
            protocol: 'TLSv1.3',
            cipher: 'TLS_AES_256_GCM_SHA384',
            serialNumber: 'ABCDEF',
            ocspStapling: true,
            supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
            certificateChain: ['CN=example.com', 'CN=R3, O=Let\'s Encrypt'],
        );

        $this->assertTrue($data->ocspStapling);
        $this->assertSame(['TLSv1.2', 'TLSv1.3'], $data->supportedProtocols);
        $this->assertCount(2, $data->certificateChain);
    }

    public function testNewFieldsDefaultValues(): void
    {
        $data = new TlsData(
            issuer: "Let's Encrypt",
            subject: 'example.com',
            san: [],
            validFrom: '2024-01-01',
            validTo: '2024-04-01',
            daysUntilExpiry: 90,
            protocol: 'TLSv1.3',
            cipher: 'TLS_AES_256_GCM_SHA384',
        );

        $this->assertFalse($data->ocspStapling);
        $this->assertSame([], $data->supportedProtocols);
        $this->assertSame([], $data->certificateChain);
    }
}
