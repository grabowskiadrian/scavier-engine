<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;
use Scavier\Detector\Infrastructure\DnsProviderDetector;
use Scavier\Engine\Context;

final class DnsProviderDetectorTest extends TestCase
{
    public function testDetectsCloudflare(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com', ns: [
            ['target' => 'ns1.cloudflare.com.'],
            ['target' => 'ns2.cloudflare.com.'],
        ]));

        $result = (new DnsProviderDetector())->detect($context);

        $this->assertSame('Cloudflare', $result['infrastructure']['dns']['value']);
        $this->assertCount(2, $result['infrastructure']['dns']['nameservers']);
    }

    public function testDetectsAwsRoute53(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com', ns: [
            ['target' => 'ns-123.awsdns-45.com.'],
        ]));

        $result = (new DnsProviderDetector())->detect($context);

        $this->assertSame('AWS Route 53', $result['infrastructure']['dns']['value']);
    }

    public function testReportsUnknownProvider(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com', ns: [
            ['target' => 'ns1.custom-dns.com.'],
        ]));

        $result = (new DnsProviderDetector())->detect($context);

        $this->assertSame('Unknown', $result['infrastructure']['dns']['value']);
        $this->assertSame(0.5, $result['infrastructure']['dns']['confidence']);
    }

    public function testReturnsNullWithoutNsRecords(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com'));

        $this->assertNull((new DnsProviderDetector())->detect($context));
    }
}
