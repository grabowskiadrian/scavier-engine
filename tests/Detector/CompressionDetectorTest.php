<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Infrastructure\CompressionDetector;
use Scavier\Engine\Context;

final class CompressionDetectorTest extends TestCase
{
    public function testDetectsGzip(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['content-encoding' => ['gzip']], body: ''));

        $result = (new CompressionDetector())->detect($context);

        $this->assertTrue($result['infrastructure']['compression']['enabled']);
        $this->assertSame('gzip', $result['infrastructure']['compression']['algorithm']);
    }

    public function testDetectsBrotli(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['content-encoding' => ['br']], body: ''));

        $result = (new CompressionDetector())->detect($context);

        $this->assertTrue($result['infrastructure']['compression']['enabled']);
        $this->assertSame('br', $result['infrastructure']['compression']['algorithm']);
    }

    public function testReportsNoCompression(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: ''));

        $result = (new CompressionDetector())->detect($context);

        $this->assertFalse($result['infrastructure']['compression']['enabled']);
        $this->assertNull($result['infrastructure']['compression']['algorithm']);
    }
}
