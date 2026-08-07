<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Technology\AnalyticsDetector;
use Scavier\Engine\Context;

final class AnalyticsDetectorTest extends TestCase
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

    public function testDetectsGA4ViaScript(): void
    {
        $result = (new AnalyticsDetector())->detect($this->context(['https://www.googletagmanager.com/gtag/js?id=G-XXXXX']));
        $names = array_column($result['marketing']['analytics']['tools'], 'value');
        $this->assertContains('Google Analytics (GA4)', $names);
    }

    public function testDetectsGTMViaScript(): void
    {
        $result = (new AnalyticsDetector())->detect($this->context(['https://www.googletagmanager.com/gtm.js?id=GTM-XXXX']));
        $names = array_column($result['marketing']['analytics']['tools'], 'value');
        $this->assertContains('Google Tag Manager', $names);
    }

    public function testDetectsHotjarViaScript(): void
    {
        $result = (new AnalyticsDetector())->detect($this->context(['https://static.hotjar.com/c/hotjar-123.js']));
        $names = array_column($result['marketing']['analytics']['tools'], 'value');
        $this->assertContains('Hotjar', $names);
    }

    public function testDetectsMatomoViaInlineScript(): void
    {
        $result = (new AnalyticsDetector())->detect($this->context(inlineScripts: ['var _paq = _paq || []; _paq.push(["trackPageView"]);']));
        $names = array_column($result['marketing']['analytics']['tools'], 'value');
        $this->assertContains('Matomo', $names);
    }

    public function testDoesNotDuplicateDetections(): void
    {
        $result = (new AnalyticsDetector())->detect($this->context(
            ['https://www.googletagmanager.com/gtag/js?id=G-XXX'],
            ['gtag("config", "G-XXX");'],
        ));
        $names = array_column($result['marketing']['analytics']['tools'], 'value');
        $ga4Count = count(array_filter($names, fn($n) => $n === 'Google Analytics (GA4)'));
        $this->assertSame(1, $ga4Count);
    }

    public function testExtractsTrackingIds(): void
    {
        $result = (new AnalyticsDetector())->detect($this->context(
            ['https://www.googletagmanager.com/gtag/js?id=G-ABC123'],
            ['gtag("config", "G-ABC123"); // GTM-XYZ789'],
        ));

        $this->assertSame('G-ABC123', $result['marketing']['analytics']['tracking_ids']['ga4']);
        $this->assertSame('GTM-XYZ789', $result['marketing']['analytics']['tracking_ids']['gtm']);
    }

    public function testReturnsNullWhenNoAnalytics(): void
    {
        $this->assertNull((new AnalyticsDetector())->detect($this->context(['/app.js'])));
    }
}
