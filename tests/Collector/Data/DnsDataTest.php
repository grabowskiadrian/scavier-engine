<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;

final class DnsDataTest extends TestCase
{
    public function testIps(): void
    {
        $data = new DnsData(
            domain: 'example.com',
            a: [['ip' => '93.184.216.34']],
            aaaa: [['ipv6' => '2606:2800:220:1:248:1893:25c8:1946']],
        );

        $ips = $data->ips();
        $this->assertContains('93.184.216.34', $ips);
        $this->assertContains('2606:2800:220:1:248:1893:25c8:1946', $ips);
    }

    public function testNameservers(): void
    {
        $data = new DnsData(
            domain: 'example.com',
            ns: [
                ['target' => 'ns1.cloudflare.com.'],
                ['target' => 'ns2.cloudflare.com.'],
            ],
        );

        $this->assertSame(['ns1.cloudflare.com', 'ns2.cloudflare.com'], $data->nameservers());
    }

    public function testMailExchangers(): void
    {
        $data = new DnsData(
            domain: 'example.com',
            mx: [
                ['target' => 'mx1.google.com.', 'pri' => 10],
                ['target' => 'mx2.google.com.', 'pri' => 20],
            ],
        );

        $this->assertSame(['mx1.google.com', 'mx2.google.com'], $data->mailExchangers());
    }

    public function testTxtValues(): void
    {
        $data = new DnsData(
            domain: 'example.com',
            txt: [['txt' => 'v=spf1 include:_spf.google.com ~all']],
        );

        $this->assertSame(['v=spf1 include:_spf.google.com ~all'], $data->txtValues());
    }

    public function testCnameTargets(): void
    {
        $data = new DnsData(
            domain: 'example.com',
            cname: [['target' => 'example.com.cdn.cloudflare.net.']],
        );

        $this->assertSame(['example.com.cdn.cloudflare.net'], $data->cnameTargets());
    }

    public function testCaaIssuers(): void
    {
        $data = new DnsData(
            domain: 'example.com',
            caa: [
                ['flags' => 0, 'tag' => 'issue', 'value' => 'letsencrypt.org'],
                ['flags' => 0, 'tag' => 'issuewild', 'value' => 'letsencrypt.org'],
                ['flags' => 0, 'tag' => 'iodef', 'value' => 'mailto:admin@example.com'],
                ['flags' => 0, 'tag' => 'issue', 'value' => 'digicert.com;cansignhttpexchanges=yes'],
            ],
        );

        $issuers = $data->caaIssuers();
        $this->assertContains('letsencrypt.org', $issuers);
        $this->assertContains('digicert.com', $issuers);
        $this->assertCount(2, $issuers);
    }

    public function testHasCaa(): void
    {
        $withCaa = new DnsData(domain: 'example.com', caa: [['flags' => 0, 'tag' => 'issue', 'value' => 'letsencrypt.org']]);
        $withoutCaa = new DnsData(domain: 'example.com');

        $this->assertTrue($withCaa->hasCaa());
        $this->assertFalse($withoutCaa->hasCaa());
    }

    public function testHasDnssec(): void
    {
        $with = new DnsData(domain: 'example.com', dnssec: true);
        $without = new DnsData(domain: 'example.com');

        $this->assertTrue($with->hasDnssec());
        $this->assertFalse($without->hasDnssec());
    }

    public function testHasTlsa(): void
    {
        $with = new DnsData(domain: 'example.com', tlsa: [['usage' => 3, 'selector' => 1, 'type' => 1, 'data' => 'abc123']]);
        $without = new DnsData(domain: 'example.com');

        $this->assertTrue($with->hasTlsa());
        $this->assertFalse($without->hasTlsa());
    }
}
