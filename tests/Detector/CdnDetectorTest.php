<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Infrastructure\CdnDetector;
use Scavier\Engine\Context;

final class CdnDetectorTest extends TestCase
{
    public function testDetectsCloudflareViaHeader(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: ['cf-ray' => ['abc123'], 'server' => ['cloudflare']],
            body: '',
        ));

        $result = (new CdnDetector())->detect($context);

        $this->assertSame('Cloudflare', $result['infrastructure']['cdn']['value']);
        $this->assertGreaterThanOrEqual(0.9, $result['infrastructure']['cdn']['confidence']);
    }

    public function testDetectsFastlyViaHeader(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: ['x-served-by' => ['cache-hhn1234']],
            body: '',
        ));

        $result = (new CdnDetector())->detect($context);

        $this->assertSame('Fastly', $result['infrastructure']['cdn']['value']);
    }

    public function testDetectsCloudFrontViaCname(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: ''));
        $context->set(new DnsData(domain: 'example.com', cname: [
            ['target' => 'd1234.cloudfront.net.'],
        ]));

        $result = (new CdnDetector())->detect($context);

        $this->assertSame('AWS CloudFront', $result['infrastructure']['cdn']['value']);
    }

    public function testReturnsNullWhenNoCdn(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['server' => ['Apache']], body: ''));
        $context->set(new DnsData(domain: 'example.com'));

        $this->assertNull((new CdnDetector())->detect($context));
    }
}
