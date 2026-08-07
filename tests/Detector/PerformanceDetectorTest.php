<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Infrastructure\PerformanceDetector;
use Scavier\Engine\Context;

final class PerformanceDetectorTest extends TestCase
{
    public function testReportsTimingMetrics(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200, headers: [], body: '<html><body>Hello</body></html>',
            responseTime: 1.234, dnsTime: 0.005, connectTime: 0.050, ttfb: 0.800,
        ));

        $result = (new PerformanceDetector())->detect($context);

        $this->assertSame(1.234, $result['infrastructure']['performance']['total_time']);
        $this->assertSame(0.005, $result['infrastructure']['performance']['dns_lookup']);
        $this->assertSame(0.050, $result['infrastructure']['performance']['tcp_connect']);
        $this->assertSame(0.800, $result['infrastructure']['performance']['ttfb']);
        $this->assertSame('good', $result['infrastructure']['performance']['ttfb_grade']);
        $this->assertGreaterThan(0, $result['infrastructure']['performance']['page_weight_bytes']);
    }

    public function testReportsPageWeightEvenWithoutTiming(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: 'hello'));

        $result = (new PerformanceDetector())->detect($context);

        $this->assertSame(5, $result['infrastructure']['performance']['page_weight_bytes']);
    }

    public function testTtfbGrading(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: '', ttfb: 0.15));

        $result = (new PerformanceDetector())->detect($context);
        $this->assertSame('good', $result['infrastructure']['performance']['ttfb_grade']);
    }
}
