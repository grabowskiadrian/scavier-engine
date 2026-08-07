<?php

namespace Scavier\Tests\Collector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Target;

final class HtmlCollectorTest extends TestCase
{
    private function runCollector(string $html): HtmlData
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: ['content-type' => ['text/html; charset=utf-8']],
            body: $html,
        ));

        (new HtmlCollector())->execute(new Target('https://example.com'), $context);

        return $context->get(HtmlData::class);
    }

    public function testExtractsTitle(): void
    {
        $data = $this->runCollector('<html><head><title>Hello World</title></head><body></body></html>');
        $this->assertSame('Hello World', $data->title);
    }

    public function testExtractsMetaTags(): void
    {
        $data = $this->runCollector('<html><head><meta name="description" content="A test page"><meta name="Generator" content="WordPress 6.0"></head><body></body></html>');
        $this->assertSame('A test page', $data->metaTag('description'));
        $this->assertSame('WordPress 6.0', $data->metaTag('generator'));
    }

    public function testExtractsScripts(): void
    {
        $data = $this->runCollector('<html><head></head><body><script src="/app.js"></script><script src="/vendor.js"></script></body></html>');
        $this->assertCount(2, $data->scripts);
        $this->assertSame('/app.js', $data->scripts[0]);
    }

    public function testExtractsInlineScripts(): void
    {
        $data = $this->runCollector('<html><head></head><body><script>var x = 1;</script><script src="/app.js"></script></body></html>');
        $this->assertCount(1, $data->inlineScripts);
        $this->assertSame('var x = 1;', $data->inlineScripts[0]);
    }

    public function testExtractsStylesheets(): void
    {
        $data = $this->runCollector('<html><head><link rel="stylesheet" href="/style.css"></head><body></body></html>');
        $this->assertCount(1, $data->stylesheets);
        $this->assertSame('/style.css', $data->stylesheets[0]);
    }

    public function testExtractsHtmlLang(): void
    {
        $data = $this->runCollector('<html lang="pl-PL"><head></head><body></body></html>');
        $this->assertSame('pl-PL', $data->htmlLang);
    }

    public function testExtractsJsonLd(): void
    {
        $json = json_encode(['@type' => 'Organization', 'name' => 'Test']);
        $data = $this->runCollector('<html><head><script type="application/ld+json">' . $json . '</script></head><body></body></html>');
        $this->assertCount(1, $data->jsonLd);
        $this->assertSame('Organization', $data->jsonLd[0]['@type']);
    }

    public function testExtractsAnchors(): void
    {
        $data = $this->runCollector('<html><head></head><body><a href="https://facebook.com/test">FB</a><a href="/local">Local</a></body></html>');
        $this->assertCount(1, $data->anchors);
        $this->assertSame('https://facebook.com/test', $data->anchors[0]);
    }

    public function testExtractsMetaProperties(): void
    {
        $data = $this->runCollector('<html><head><meta property="og:title" content="Test Title"></head><body></body></html>');
        $this->assertSame('Test Title', $data->metaProperties['og:title']);
    }

    public function testSkipsNonHtmlContent(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: ['content-type' => ['application/json']],
            body: '{"key": "value"}',
        ));

        (new HtmlCollector())->execute(new Target('https://example.com'), $context);

        $this->assertNull($context->get(HtmlData::class));
    }
}
