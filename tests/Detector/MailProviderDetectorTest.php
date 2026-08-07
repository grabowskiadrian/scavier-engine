<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;
use Scavier\Detector\Infrastructure\MailProviderDetector;
use Scavier\Engine\Context;

final class MailProviderDetectorTest extends TestCase
{
    private function contextWithMx(array $mx): Context
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com', mx: $mx));
        return $context;
    }

    public function testDetectsGoogleWorkspace(): void
    {
        $result = (new MailProviderDetector())->detect($this->contextWithMx([
            ['target' => 'aspmx.l.google.com.', 'pri' => 1],
        ]));

        $this->assertSame('Google Workspace', $result['infrastructure']['mail'][0]['value']);
        $this->assertSame(0.95, $result['infrastructure']['mail'][0]['confidence']);
    }

    public function testDetectsMicrosoft365(): void
    {
        $result = (new MailProviderDetector())->detect($this->contextWithMx([
            ['target' => 'example-com.mail.protection.outlook.com.', 'pri' => 0],
        ]));

        $this->assertSame('Microsoft 365', $result['infrastructure']['mail'][0]['value']);
    }

    public function testReportsUnknownForCustomMx(): void
    {
        $result = (new MailProviderDetector())->detect($this->contextWithMx([
            ['target' => 'mail.custom-server.com.', 'pri' => 10],
        ]));

        $this->assertSame('Unknown', $result['infrastructure']['mail'][0]['value']);
        $this->assertSame(0.5, $result['infrastructure']['mail'][0]['confidence']);
    }

    public function testReturnsNullWithoutMxRecords(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com'));

        $this->assertNull((new MailProviderDetector())->detect($context));
    }
}
