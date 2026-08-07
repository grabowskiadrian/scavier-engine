<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Marketing\AdNetworkDetector;
use Scavier\Engine\Context;

final class AdNetworkDetectorTest extends TestCase
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

    public function testDetectsAdSense(): void
    {
        $result = (new AdNetworkDetector())->detect($this->context(['https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js']));
        $this->assertSame('Google AdSense', $result['marketing']['advertising'][0]['value']);
    }

    public function testDetectsAdSenseViaInline(): void
    {
        $result = (new AdNetworkDetector())->detect($this->context(inlineScripts: ['(adsbygoogle = window.adsbygoogle || []).push({})']));
        $this->assertSame('Google AdSense', $result['marketing']['advertising'][0]['value']);
    }

    public function testDetectsMediavine(): void
    {
        $result = (new AdNetworkDetector())->detect($this->context(['https://scripts.mediavine.com/tags/site.js']));
        $this->assertSame('Mediavine', $result['marketing']['advertising'][0]['value']);
    }

    public function testReturnsNullWhenNoAds(): void
    {
        $this->assertNull((new AdNetworkDetector())->detect($this->context(['/app.js'])));
    }
}
