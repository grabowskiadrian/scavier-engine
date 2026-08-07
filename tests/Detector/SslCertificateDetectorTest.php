<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\TlsData;
use Scavier\Detector\Security\SslCertificateDetector;
use Scavier\Engine\Context;

final class SslCertificateDetectorTest extends TestCase
{
    private function contextWithTls(string $issuer = 'R3', int $daysUntilExpiry = 60): Context
    {
        $context = new Context();
        $context->set(new TlsData(
            issuer: $issuer,
            subject: 'example.com',
            san: ['example.com', '*.example.com'],
            validFrom: '2025-01-01',
            validTo: '2025-12-31',
            daysUntilExpiry: $daysUntilExpiry,
            protocol: 'TLSv1.3',
            cipher: 'TLS_AES_256_GCM_SHA384',
            serialNumber: 'ABCD1234',
        ));
        return $context;
    }

    public function testDetectsCertificateFacts(): void
    {
        $result = (new SslCertificateDetector())->detect($this->contextWithTls("Let's Encrypt"));

        $ssl = $result['domain']['ssl'];
        $this->assertSame("Let's Encrypt", $ssl['issuer']);
        $this->assertSame('example.com', $ssl['subject']);
        $this->assertSame(2, $ssl['san_count']);
    }

    public function testOutputsTlsConfig(): void
    {
        $result = (new SslCertificateDetector())->detect($this->contextWithTls("Let's Encrypt"));

        $tls = $result['security']['tls'];
        $this->assertSame('TLSv1.3', $tls['protocol']);
        $this->assertSame('TLS_AES_256_GCM_SHA384', $tls['cipher']);
    }

    public function testNormalizesIssuer(): void
    {
        $result = (new SslCertificateDetector())->detect($this->contextWithTls('Cloudflare Inc ECC CA-3'));
        $this->assertSame('Cloudflare', $result['domain']['ssl']['issuer']);
    }

    public function testAuditExpiringSoon(): void
    {
        $result = (new SslCertificateDetector())->detect($this->contextWithTls("Let's Encrypt", 15));

        $issues = $result['audit']['ssl_issues'];
        $this->assertSame('certificate_expiring_soon', $issues[0]['issue']);
        $this->assertSame('warning', $issues[0]['severity']);
    }

    public function testAuditExpired(): void
    {
        $result = (new SslCertificateDetector())->detect($this->contextWithTls("Let's Encrypt", -5));

        $issues = $result['audit']['ssl_issues'];
        $this->assertSame('certificate_expired', $issues[0]['issue']);
        $this->assertSame('critical', $issues[0]['severity']);
    }

    public function testNoAuditWhenHealthy(): void
    {
        $result = (new SslCertificateDetector())->detect($this->contextWithTls("Let's Encrypt", 90));
        $this->assertArrayNotHasKey('audit', $result);
    }

    public function testReturnsNullWithoutTlsData(): void
    {
        $this->assertNull((new SslCertificateDetector())->detect(new Context()));
    }

    public function testIncludesOcspAndProtocols(): void
    {
        $context = new Context();
        $context->set(new TlsData(
            issuer: "Let's Encrypt", subject: 'example.com',
            san: ['example.com'],
            validFrom: '2025-01-01', validTo: '2025-12-31', daysUntilExpiry: 60,
            protocol: 'TLSv1.3', cipher: 'AES256',
            ocspStapling: true,
            supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
            certificateChain: ['CN=example.com', "CN=R3, O=Let's Encrypt"],
        ));

        $result = (new SslCertificateDetector())->detect($context);

        $this->assertTrue($result['security']['tls']['ocsp_stapling']);
        $this->assertSame(['TLSv1.2', 'TLSv1.3'], $result['security']['tls']['supported_protocols']);
        $this->assertSame(2, $result['domain']['ssl']['chain_length']);
    }

    public function testAuditLegacyProtocols(): void
    {
        $context = new Context();
        $context->set(new TlsData(
            issuer: 'LE', subject: 'example.com', san: ['example.com'],
            validFrom: '2025-01-01', validTo: '2025-12-31', daysUntilExpiry: 60,
            protocol: 'TLSv1.2', cipher: 'AES256',
            supportedProtocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
        ));

        $result = (new SslCertificateDetector())->detect($context);

        $legacyIssue = null;
        foreach ($result['audit']['ssl_issues'] as $issue) {
            if ($issue['issue'] === 'legacy_tls_protocols') {
                $legacyIssue = $issue;
            }
        }

        $this->assertNotNull($legacyIssue);
        $this->assertSame(['TLSv1', 'TLSv1.1'], $legacyIssue['protocols']);
    }
}
