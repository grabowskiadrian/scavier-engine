<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\Data\WhoisData;
use Scavier\Detector\Infrastructure\HostingDetector;
use Scavier\Engine\Context;

final class HostingDetectorTest extends TestCase
{
    public function testDetectsNetlifyViaServerHeader(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['server' => ['Netlify']], body: ''));
        $context->set(new DnsData(domain: 'example.com'));

        $result = (new HostingDetector())->detect($context);

        $this->assertSame('Netlify', $result['infrastructure']['hosting']['value']);
    }

    public function testDetectsVercelViaServerHeader(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['server' => ['Vercel']], body: ''));
        $context->set(new DnsData(domain: 'example.com'));

        $result = (new HostingDetector())->detect($context);

        $this->assertSame('Vercel', $result['infrastructure']['hosting']['value']);
    }

    public function testDetectsHerokuViaCname(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: ''));
        $context->set(new DnsData(domain: 'example.com', cname: [
            ['target' => 'myapp.herokuapp.com.'],
        ]));

        $result = (new HostingDetector())->detect($context);

        $this->assertSame('Heroku', $result['infrastructure']['hosting']['value']);
    }

    public function testDetectsHetznerViaIp(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: ''));
        $context->set(new DnsData(domain: 'example.com', a: [['ip' => '136.243.100.50']]));

        $result = (new HostingDetector())->detect($context);

        $this->assertSame('Hetzner', $result['infrastructure']['hosting']['value']);
        $this->assertSame(0.7, $result['infrastructure']['hosting']['confidence']);
    }

    public function testReturnsNullWhenUnknown(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['server' => ['Apache']], body: ''));
        $context->set(new DnsData(domain: 'example.com', a: [['ip' => '1.2.3.4']]));

        $this->assertNull((new HostingDetector())->detect($context));
    }

    public function testDetectsViaWhoisAsn(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['server' => ['Apache']], body: ''));
        $context->set(new DnsData(domain: 'example.com', a: [['ip' => '1.2.3.4']]));
        $context->set(new WhoisData(
            asn: 24940,
            asnName: 'HETZNER-AS',
            organization: 'Hetzner Online GmbH',
            country: 'DE',
        ));

        $result = (new HostingDetector())->detect($context);

        $this->assertSame('Hetzner', $result['infrastructure']['hosting']['value']);
        $this->assertSame(0.8, $result['infrastructure']['hosting']['confidence']);
        $this->assertStringContainsString('AS24940', $result['infrastructure']['hosting']['evidence']);
    }

    public function testDetectsScalewayViaWhois(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: ''));
        $context->set(new DnsData(domain: 'example.com', a: [['ip' => '1.2.3.4']]));
        $context->set(new WhoisData(
            asn: 12876,
            organization: 'SCALEWAY S.A.S.',
        ));

        $result = (new HostingDetector())->detect($context);

        $this->assertSame('Scaleway', $result['infrastructure']['hosting']['value']);
    }
}
