<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\WhoisData;

final class WhoisDataTest extends TestCase
{
    public function testStoresAllFields(): void
    {
        $data = new WhoisData(
            asn: 13335,
            asnName: 'CLOUDFLARENET',
            netName: 'CLOUDFLARE-NET',
            netRange: '104.16.0.0 - 104.31.255.255',
            organization: 'Cloudflare, Inc.',
            country: 'US',
            abuseContact: 'abuse@cloudflare.com',
        );

        $this->assertSame(13335, $data->asn);
        $this->assertSame('CLOUDFLARENET', $data->asnName);
        $this->assertSame('CLOUDFLARE-NET', $data->netName);
        $this->assertSame('104.16.0.0 - 104.31.255.255', $data->netRange);
        $this->assertSame('Cloudflare, Inc.', $data->organization);
        $this->assertSame('US', $data->country);
        $this->assertSame('abuse@cloudflare.com', $data->abuseContact);
    }

    public function testDefaultsToNull(): void
    {
        $data = new WhoisData();

        $this->assertNull($data->asn);
        $this->assertNull($data->asnName);
        $this->assertNull($data->netName);
        $this->assertNull($data->organization);
        $this->assertNull($data->country);
        $this->assertNull($data->abuseContact);
    }
}
