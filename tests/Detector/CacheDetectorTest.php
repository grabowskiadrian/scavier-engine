<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Infrastructure\CacheDetector;
use Scavier\Engine\Context;

final class CacheDetectorTest extends TestCase
{
    public function testDetectsCacheHeaders(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [
            'cache-control' => ['public, max-age=3600'],
            'etag' => ['"abc123"'],
            'x-cache' => ['HIT'],
        ], body: ''));

        $result = (new CacheDetector())->detect($context);

        $this->assertSame('public, max-age=3600', $result['infrastructure']['cache']['cache_control']);
        $this->assertTrue($result['infrastructure']['cache']['etag']);
        $this->assertSame('HIT', $result['infrastructure']['cache']['x_cache']);
    }

    public function testDetectsCloudflareCacheStatus(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [
            'cf-cache-status' => ['DYNAMIC'],
        ], body: ''));

        $result = (new CacheDetector())->detect($context);

        $this->assertSame('DYNAMIC', $result['infrastructure']['cache']['cf_cache_status']);
    }

    public function testReturnsNullWhenNoCacheHeaders(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: ''));

        $this->assertNull((new CacheDetector())->detect($context));
    }
}
