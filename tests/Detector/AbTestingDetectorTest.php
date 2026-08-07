<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Marketing\AbTestingDetector;
use Scavier\Engine\Context;

final class AbTestingDetectorTest extends TestCase
{
    private function context(array $scripts = [], array $inlineScripts = []): Context
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: $scripts, inlineScripts: $inlineScripts,
            stylesheets: [], metaProperties: [], bodyText: '',
        ));
        return $context;
    }

    public function testDetectsOptimizely(): void
    {
        $result = (new AbTestingDetector())->detect($this->context(['https://cdn.optimizely.com/js/12345.js']));
        $this->assertSame('Optimizely', $result['marketing']['ab_testing'][0]['value']);
    }

    public function testDetectsVWO(): void
    {
        $result = (new AbTestingDetector())->detect($this->context(['https://dev.visualwebsiteoptimizer.com/lib/12345.js']));
        $this->assertSame('VWO', $result['marketing']['ab_testing'][0]['value']);
    }

    public function testDetectsLaunchDarklyViaInline(): void
    {
        $result = (new AbTestingDetector())->detect($this->context(inlineScripts: ['const client = LDClient.initialize("key")']));
        $this->assertSame('LaunchDarkly', $result['marketing']['ab_testing'][0]['value']);
    }

    public function testReturnsNullWhenNoAbTesting(): void
    {
        $this->assertNull((new AbTestingDetector())->detect($this->context(['/app.js'])));
    }
}
