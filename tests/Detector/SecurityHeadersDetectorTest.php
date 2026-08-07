<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Security\SecurityHeadersDetector;
use Scavier\Engine\Context;

final class SecurityHeadersDetectorTest extends TestCase
{
    public function testReportsAllMissingHeaders(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: ''));

        $result = (new SecurityHeadersDetector())->detect($context);

        $this->assertSame(0.0, $result['audit']['security_score']['score']);
        $this->assertEmpty($result['security']['headers']['present']);
        $this->assertCount(10, $result['security']['headers']['missing']);
    }

    public function testReportsPresentHeaders(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [
            'strict-transport-security' => ['max-age=31536000'],
            'x-content-type-options' => ['nosniff'],
            'x-frame-options' => ['DENY'],
        ], body: ''));

        $result = (new SecurityHeadersDetector())->detect($context);

        $this->assertSame(0.3, $result['audit']['security_score']['score']);
        $this->assertCount(3, $result['security']['headers']['present']);
        $this->assertCount(7, $result['security']['headers']['missing']);
    }

    public function testPerfectScore(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [
            'strict-transport-security' => ['max-age=31536000'],
            'content-security-policy' => ["default-src 'self'"],
            'x-content-type-options' => ['nosniff'],
            'x-frame-options' => ['DENY'],
            'referrer-policy' => ['strict-origin'],
            'permissions-policy' => ['camera=()'],
            'x-xss-protection' => ['1; mode=block'],
            'cross-origin-opener-policy' => ['same-origin'],
            'cross-origin-embedder-policy' => ['require-corp'],
            'cross-origin-resource-policy' => ['same-origin'],
        ], body: ''));

        $result = (new SecurityHeadersDetector())->detect($context);
        $this->assertSame(1.0, $result['audit']['security_score']['score']);
        $this->assertSame('A', $result['audit']['security_score']['grade']);
    }

    public function testFactsAndAuditSeparated(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [
            'strict-transport-security' => ['max-age=31536000'],
        ], body: ''));

        $result = (new SecurityHeadersDetector())->detect($context);

        // Facts in security.headers
        $this->assertArrayHasKey('present', $result['security']['headers']);
        $this->assertArrayHasKey('missing', $result['security']['headers']);
        $this->assertArrayNotHasKey('score', $result['security']['headers']);
        $this->assertArrayNotHasKey('grade', $result['security']['headers']);

        // Analysis in audit.security_score
        $this->assertArrayHasKey('score', $result['audit']['security_score']);
        $this->assertArrayHasKey('grade', $result['audit']['security_score']);
    }
}
