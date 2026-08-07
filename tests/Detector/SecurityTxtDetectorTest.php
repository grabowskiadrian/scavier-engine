<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DiscoveryData;
use Scavier\Detector\Security\SecurityTxtDetector;
use Scavier\Engine\Context;

final class SecurityTxtDetectorTest extends TestCase
{
    public function testDetectsSecurityTxt(): void
    {
        $body = "Contact: security@example.com\nExpires: 2025-12-31T00:00:00Z\nPreferred-Languages: en\nPolicy: https://example.com/security-policy";

        $context = new Context();
        $context->set(new DiscoveryData(['/.well-known/security.txt' => ['status' => 200, 'body' => $body]]));

        $result = (new SecurityTxtDetector())->detect($context);

        $this->assertTrue($result['security']['security_txt']['exists']);
        $this->assertSame(['security@example.com'], $result['security']['security_txt']['fields']['contact']);
        $this->assertArrayHasKey('expires', $result['security']['security_txt']['fields']);
    }

    public function testReturnsNullWhenNotFound(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/.well-known/security.txt' => ['status' => 404, 'body' => null]]));

        $this->assertNull((new SecurityTxtDetector())->detect($context));
    }
}
