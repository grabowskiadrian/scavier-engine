<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Technology\LibraryDetector;
use Scavier\Engine\Context;

final class LibraryDetectorTest extends TestCase
{
    private function contextWithScripts(array $scripts): Context
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null,
            meta: [],
            scripts: $scripts,
            inlineScripts: [],
            stylesheets: [],
            metaProperties: [],
            bodyText: '',
        ));

        return $context;
    }

    public function testDetectsJQuery(): void
    {
        $context = $this->contextWithScripts([
            'https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js',
        ]);

        $result = (new LibraryDetector())->detect($context);

        $this->assertNotNull($result);
        $names = array_column($result['technology']['libraries'], 'value');
        $this->assertContains('jQuery', $names);
    }

    public function testDetectsBootstrap(): void
    {
        $context = $this->contextWithScripts([
            'https://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.min.js',
        ]);

        $result = (new LibraryDetector())->detect($context);

        $this->assertNotNull($result);
        $names = array_column($result['technology']['libraries'], 'value');
        $this->assertContains('Bootstrap', $names);
    }

    public function testReturnsNullWhenNoMatch(): void
    {
        $context = $this->contextWithScripts(['/assets/custom-app.js']);

        $this->assertNull((new LibraryDetector())->detect($context));
    }

    public function testReturnsNullWithoutHtmlData(): void
    {
        $this->assertNull((new LibraryDetector())->detect(new Context()));
    }
}
