<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\CrtshData;
use Scavier\Collector\Data\SubdomainDnsData;
use Scavier\Collector\Data\TlsData;
use Scavier\Detector\Infrastructure\SubdomainDetector;
use Scavier\Engine\Context;

final class SubdomainDetectorTest extends TestCase
{
    public function testDetectsSubdomainsWithServices(): void
    {
        $context = new Context();
        $context->set(new TlsData(
            issuer: 'LE', subject: 'example.com',
            san: ['example.com', 'api.example.com', 'app.example.com', 'mail.example.com'],
            validFrom: '2025-01-01', validTo: '2025-12-31', daysUntilExpiry: 60,
            protocol: 'TLSv1.3', cipher: 'AES256',
        ));

        $result = (new SubdomainDetector())->detect($context);

        $this->assertSame(4, $result['infrastructure']['subdomains']['count']);
        $domains = $result['infrastructure']['subdomains']['domains'];
        $services = array_column($domains, 'service', 'name');
        $this->assertSame('api', $services['api.example.com']);
        $this->assertSame('app', $services['app.example.com']);
        $this->assertSame('mail', $services['mail.example.com']);
        $this->assertNull($services['example.com']);
    }

    public function testSkipsWildcards(): void
    {
        $context = new Context();
        $context->set(new TlsData(
            issuer: 'LE', subject: 'example.com',
            san: ['example.com', '*.example.com', 'api.example.com'],
            validFrom: '2025-01-01', validTo: '2025-12-31', daysUntilExpiry: 60,
            protocol: 'TLSv1.3', cipher: 'AES256',
        ));

        $result = (new SubdomainDetector())->detect($context);

        $this->assertSame(2, $result['infrastructure']['subdomains']['count']);
    }

    public function testReturnsNullForSingleDomain(): void
    {
        $context = new Context();
        $context->set(new TlsData(
            issuer: 'LE', subject: 'example.com',
            san: ['example.com'],
            validFrom: '2025-01-01', validTo: '2025-12-31', daysUntilExpiry: 60,
            protocol: 'TLSv1.3', cipher: 'AES256',
        ));

        $this->assertNull((new SubdomainDetector())->detect($context));
    }

    public function testCombinesCrtshAndDnsBrute(): void
    {
        $context = new Context();

        // TLS SAN has 2 domains
        $context->set(new TlsData(
            issuer: 'LE', subject: 'example.com',
            san: ['example.com', 'www.example.com'],
            validFrom: '2025-01-01', validTo: '2025-12-31', daysUntilExpiry: 60,
            protocol: 'TLSv1.3', cipher: 'AES256',
        ));

        // crt.sh adds more
        $context->set(new CrtshData(
            domain: 'example.com',
            subdomains: ['api.example.com', 'staging.example.com', 'www.example.com'],
        ));

        // DNS brute adds even more
        $context->set(new SubdomainDnsData(
            domain: 'example.com',
            resolved: [
                'mail.example.com' => ['ip' => '1.2.3.4', 'cname' => null],
                'api.example.com' => ['ip' => '5.6.7.8', 'cname' => null],
            ],
        ));

        $result = (new SubdomainDetector())->detect($context);

        // Should have: example.com, www, api, staging, mail = 5 unique
        $this->assertSame(5, $result['infrastructure']['subdomains']['count']);

        $domains = array_column($result['infrastructure']['subdomains']['domains'], null, 'name');

        // www from TLS SAN
        $this->assertSame('tls_san', $domains['www.example.com']['source']);
        // staging from crt.sh
        $this->assertSame('certificate_transparency', $domains['staging.example.com']['source']);
        // mail from DNS brute (not in TLS or crt.sh)
        $this->assertSame('dns_brute', $domains['mail.example.com']['source']);
        // api from crt.sh (TLS didn't have it, crt.sh found it first)
        $this->assertSame('certificate_transparency', $domains['api.example.com']['source']);
        // api should have IP from DNS brute resolution
        $this->assertSame('5.6.7.8', $domains['api.example.com']['ip']);

        $this->assertContains('tls_san', $result['infrastructure']['subdomains']['sources']);
        $this->assertContains('certificate_transparency', $result['infrastructure']['subdomains']['sources']);
        $this->assertContains('dns_brute', $result['infrastructure']['subdomains']['sources']);
    }

    public function testDnsBruteOnlySource(): void
    {
        $context = new Context();
        $context->set(new SubdomainDnsData(
            domain: 'example.com',
            resolved: [
                'mail.example.com' => ['ip' => '1.2.3.4', 'cname' => null],
                'admin.example.com' => ['ip' => null, 'cname' => 'admin.cdn.example.com'],
            ],
        ));

        $result = (new SubdomainDetector())->detect($context);

        $this->assertSame(2, $result['infrastructure']['subdomains']['count']);
        $domains = array_column($result['infrastructure']['subdomains']['domains'], null, 'name');
        $this->assertSame('admin', $domains['admin.example.com']['service']);
        $this->assertSame('admin.cdn.example.com', $domains['admin.example.com']['cname']);
    }
}
