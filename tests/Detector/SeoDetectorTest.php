<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Seo\RobotsDetector;
use Scavier\Detector\Seo\SeoDetector;
use Scavier\Detector\Seo\SitemapDetector;
use Scavier\Engine\Context;

final class SeoDetectorTest extends TestCase
{
    private function fullContext(): Context
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: 'Test Page',
            meta: ['description' => 'A great page', 'viewport' => 'width=device-width'],
            scripts: [], inlineScripts: [], stylesheets: [],
            metaProperties: ['og:title' => 'Test', 'twitter:card' => 'summary'],
            bodyText: '',
            htmlLang: 'en',
            links: [['rel' => 'canonical', 'href' => 'https://example.com/']],
            jsonLd: [['@type' => 'WebPage']],
        ));

        $context->setDetectorResult(RobotsDetector::class, ['seo' => ['robots' => ['exists' => true]]]);
        $context->setDetectorResult(SitemapDetector::class, ['seo' => ['sitemap' => ['exists' => true]]]);

        return $context;
    }

    public function testPerfectSeoScore(): void
    {
        $result = (new SeoDetector())->detect($this->fullContext());

        $this->assertSame(1.0, $result['audit']['seo_score']['score']);
        $this->assertSame(11, $result['audit']['seo_score']['passed']);
    }

    public function testPartialSeoScore(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: 'Test', meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));

        $result = (new SeoDetector())->detect($context);

        $this->assertLessThan(1.0, $result['audit']['seo_score']['score']);
        $this->assertTrue($result['seo']['overview']['checks']['title']['present']);
        $this->assertFalse($result['seo']['overview']['checks']['meta_description']['present']);
    }

    public function testFactsAndScoreSeparated(): void
    {
        $result = (new SeoDetector())->detect($this->fullContext());

        // Facts in seo.overview
        $this->assertArrayHasKey('checks', $result['seo']['overview']);
        $this->assertArrayNotHasKey('score', $result['seo']['overview']);

        // Score in audit.seo_score
        $this->assertArrayHasKey('score', $result['audit']['seo_score']);
        $this->assertArrayHasKey('passed', $result['audit']['seo_score']);
        $this->assertArrayHasKey('total', $result['audit']['seo_score']);
    }
}
