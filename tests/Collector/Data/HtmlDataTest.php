<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;

final class HtmlDataTest extends TestCase
{
    private function makeHtmlData(array $scripts = [], array $inlineScripts = []): HtmlData
    {
        return new HtmlData(
            title: 'Test Page',
            meta: ['description' => 'A test page', 'generator' => 'WordPress'],
            scripts: $scripts,
            inlineScripts: $inlineScripts,
            stylesheets: ['style.css'],
            metaProperties: ['og:title' => 'Test'],
            bodyText: 'Hello world',
        );
    }

    public function testMetaTagLookup(): void
    {
        $data = $this->makeHtmlData();

        $this->assertSame('A test page', $data->metaTag('description'));
        $this->assertSame('WordPress', $data->metaTag('Generator'));
        $this->assertNull($data->metaTag('missing'));
    }

    public function testHasScriptMatching(): void
    {
        $data = $this->makeHtmlData([
            'https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js',
            '/assets/app.js',
        ]);

        $this->assertTrue($data->hasScriptMatching('/jquery/i'));
        $this->assertFalse($data->hasScriptMatching('/react/i'));
    }

    public function testScriptsMatching(): void
    {
        $data = $this->makeHtmlData([
            'https://cdn.jsdelivr.net/npm/jquery.min.js',
            'https://cdn.jsdelivr.net/npm/bootstrap.min.js',
            '/assets/app.js',
        ]);

        $matches = $data->scriptsMatching('/cdn\.jsdelivr\.net/');

        $this->assertCount(2, $matches);
    }

    public function testScriptsMatchingReturnsEmptyWhenNoMatch(): void
    {
        $data = $this->makeHtmlData(['/app.js']);

        $this->assertSame([], $data->scriptsMatching('/react/'));
    }
}
