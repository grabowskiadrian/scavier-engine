<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Technology\FrameworkDetector;
use Scavier\Engine\Context;

final class FrameworkDetectorTest extends TestCase
{
    private function context(array $scripts = [], array $inlineScripts = [], array $cookies = [], string $body = ''): Context
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: $body, cookies: $cookies));
        $context->set(new HtmlData(
            title: null, meta: [], scripts: $scripts, inlineScripts: $inlineScripts,
            stylesheets: [], metaProperties: [], bodyText: '',
        ));
        return $context;
    }

    public function testDetectsReactViaScript(): void
    {
        $result = (new FrameworkDetector())->detect($this->context(['/static/js/react-dom.production.min.js']));
        $names = array_column($result['technology']['frameworks'], 'value');
        $this->assertContains('React', $names);
    }

    public function testDetectsNextJsViaInlineScript(): void
    {
        $result = (new FrameworkDetector())->detect($this->context(inlineScripts: ['<script id="__NEXT_DATA__" type="application/json">{}']));
        $names = array_column($result['technology']['frameworks'], 'value');
        $this->assertContains('Next.js', $names);
    }

    public function testDetectsLaravelViaCookie(): void
    {
        $result = (new FrameworkDetector())->detect($this->context(cookies: ['laravel_session' => 'abc']));
        $names = array_column($result['technology']['frameworks'], 'value');
        $this->assertContains('Laravel', $names);
    }

    public function testDetectsAngularViaHtml(): void
    {
        $result = (new FrameworkDetector())->detect($this->context(body: '<app-root ng-version="17.0.0">'));
        $names = array_column($result['technology']['frameworks'], 'value');
        $this->assertContains('Angular', $names);
    }

    public function testReturnsNullWhenNoFramework(): void
    {
        $this->assertNull((new FrameworkDetector())->detect($this->context()));
    }

    public function testDoesNotDuplicateDetections(): void
    {
        // React via script + HTML pattern should only appear once
        $result = (new FrameworkDetector())->detect($this->context(
            ['/react-dom.min.js'],
            [],
            [],
            '<div data-reactroot="">',
        ));
        $names = array_column($result['technology']['frameworks'], 'value');
        $reactCount = count(array_filter($names, fn($n) => $n === 'React'));
        $this->assertSame(1, $reactCount);
    }
}
