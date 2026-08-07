<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;
use Scavier\Detector\Infrastructure\Ipv6Detector;
use Scavier\Engine\Context;

final class Ipv6DetectorTest extends TestCase
{
    public function testDetectsDualStack(): void
    {
        $context = new Context();
        $context->set(new DnsData(
            domain: 'example.com',
            a: [['ip' => '93.184.216.34']],
            aaaa: [['ipv6' => '2606:2800:220:1:248:1893:25c8:1946']],
        ));

        $result = (new Ipv6Detector())->detect($context);

        $this->assertSame('dual-stack', $result['infrastructure']['ip']['stack']);
        $this->assertTrue($result['infrastructure']['ip']['ipv4']);
        $this->assertTrue($result['infrastructure']['ip']['ipv6']);
    }

    public function testDetectsIpv4Only(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com', a: [['ip' => '1.2.3.4']]));

        $result = (new Ipv6Detector())->detect($context);

        $this->assertSame('ipv4-only', $result['infrastructure']['ip']['stack']);
    }

    public function testReturnsNullWithoutDns(): void
    {
        $this->assertNull((new Ipv6Detector())->detect(new Context()));
    }
}
