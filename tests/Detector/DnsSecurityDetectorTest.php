<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;
use Scavier\Detector\Security\DnsSecurityDetector;
use Scavier\Engine\Context;

final class DnsSecurityDetectorTest extends TestCase
{
    public function testDetectsFullDnsSecurity(): void
    {
        $context = new Context();
        $context->set(new DnsData(
            domain: 'example.com',
            dnssec: true,
            caa: [
                ['flags' => 0, 'tag' => 'issue', 'value' => 'letsencrypt.org'],
                ['flags' => 0, 'tag' => 'issuewild', 'value' => 'letsencrypt.org'],
            ],
            tlsa: [
                ['usage' => 3, 'selector' => 1, 'type' => 1, 'data' => 'abc123'],
            ],
        ));

        $result = (new DnsSecurityDetector())->detect($context);
        $dns = $result['domain']['dns_security'];

        $this->assertTrue($dns['dnssec']['configured']);
        $this->assertTrue($dns['caa']['configured']);
        $this->assertContains('letsencrypt.org', $dns['caa']['issuers']);
        $this->assertTrue($dns['dane']['configured']);
        $this->assertSame(1, $dns['dane']['records']);
    }

    public function testDetectsMissingDnsSecurity(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com'));

        $result = (new DnsSecurityDetector())->detect($context);
        $dns = $result['domain']['dns_security'];

        $this->assertFalse($dns['dnssec']['configured']);
        $this->assertFalse($dns['caa']['configured']);
        $this->assertSame([], $dns['caa']['issuers']);
        $this->assertArrayNotHasKey('dane', $dns);
    }

    public function testReturnsNullWithoutDnsData(): void
    {
        $this->assertNull((new DnsSecurityDetector())->detect(new Context()));
    }
}
