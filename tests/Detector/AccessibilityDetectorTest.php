<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Content\AccessibilityDetector;
use Scavier\Engine\Context;

final class AccessibilityDetectorTest extends TestCase
{
    public function testDetectsBasicChecks(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: ['viewport' => 'width=device-width'], scripts: [],
            inlineScripts: [], stylesheets: [], metaProperties: [], bodyText: '',
            htmlLang: 'en',
        ));

        $result = (new AccessibilityDetector())->detect($context);

        $this->assertTrue($result['content']['accessibility']['checks']['lang_attribute']);
        $this->assertTrue($result['content']['accessibility']['checks']['viewport']);
        $this->assertFalse($result['content']['accessibility']['checks']['overlay_tool']);
    }

    public function testDetectsAccessiBeOverlay(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: ['https://acsbapp.com/apps/app/dist/js/app.js'],
            inlineScripts: [], stylesheets: [], metaProperties: [], bodyText: '',
        ));

        $result = (new AccessibilityDetector())->detect($context);

        $this->assertTrue($result['content']['accessibility']['checks']['overlay_tool']);
        $this->assertContains('AccessiBe', $result['content']['accessibility']['overlay_tools']);
    }

    public function testReportsMissingChecks(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));

        $result = (new AccessibilityDetector())->detect($context);

        $this->assertFalse($result['content']['accessibility']['checks']['lang_attribute']);
        $this->assertFalse($result['content']['accessibility']['checks']['viewport']);
        $this->assertSame(0, $result['content']['accessibility']['passed']);
    }
}
