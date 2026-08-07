<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;
use Scavier\Detector\Security\EmailSecurityDetector;
use Scavier\Engine\Context;

final class EmailSecurityDetectorTest extends TestCase
{
    public function testDetectsSpfAndDmarc(): void
    {
        $context = new Context();
        $context->set(new DnsData(
            domain: 'example.com',
            txt: [
                ['txt' => 'v=spf1 include:_spf.google.com ~all'],
                ['txt' => 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'],
            ],
        ));

        $result = (new EmailSecurityDetector())->detect($context);

        $this->assertTrue($result['security']['email']['spf']['configured']);
        $this->assertStringContainsString('spf1', $result['security']['email']['spf']['value']);
        $this->assertTrue($result['security']['email']['dmarc']['configured']);
        $this->assertSame('reject', $result['security']['email']['dmarc']['policy']);
    }

    public function testDetectsMissingSecurity(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com', txt: [['txt' => 'google-site-verification=abc']]));

        $result = (new EmailSecurityDetector())->detect($context);

        $this->assertFalse($result['security']['email']['spf']['configured']);
        $this->assertFalse($result['security']['email']['dmarc']['configured']);
    }

    public function testDetectsDmarcPolicyNone(): void
    {
        $context = new Context();
        $context->set(new DnsData(
            domain: 'example.com',
            txt: [['txt' => 'v=DMARC1; p=none']],
        ));

        $result = (new EmailSecurityDetector())->detect($context);

        $this->assertSame('none', $result['security']['email']['dmarc']['policy']);
    }

}
