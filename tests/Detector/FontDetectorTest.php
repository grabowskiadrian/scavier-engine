<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Technology\FontDetector;
use Scavier\Engine\Context;

final class FontDetectorTest extends TestCase
{
    public function testDetectsGoogleFontsWithFamilies(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: ['https://fonts.googleapis.com/css2?family=Inter&family=Roboto:wght@400;700&display=swap'],
            metaProperties: [], bodyText: '',
        ));

        $result = (new FontDetector())->detect($context);

        $this->assertSame('Google Fonts', $result['technology']['fonts'][0]['value']);
        $this->assertContains('Inter', $result['technology']['fonts'][0]['families']);
        $this->assertContains('Roboto', $result['technology']['fonts'][0]['families']);
    }

    public function testDetectsAdobeFonts(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: ['https://use.typekit.net/abc123.css'],
            metaProperties: [], bodyText: '',
        ));

        $result = (new FontDetector())->detect($context);

        $this->assertSame('Adobe Fonts', $result['technology']['fonts'][0]['value']);
    }

    public function testDetectsViaPreconnect(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            links: [['rel' => 'preconnect', 'href' => 'https://fonts.gstatic.com']],
        ));

        $result = (new FontDetector())->detect($context);

        $this->assertSame('Google Fonts', $result['technology']['fonts'][0]['value']);
        $this->assertSame(0.7, $result['technology']['fonts'][0]['confidence']);
    }

    public function testReturnsNullWhenNoFonts(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: ['/style.css'], metaProperties: [], bodyText: '',
        ));

        $this->assertNull((new FontDetector())->detect($context));
    }
}
