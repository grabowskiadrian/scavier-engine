<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Content\LanguageDetector;
use Scavier\Engine\Context;

final class LanguageDetectorTest extends TestCase
{
    public function testDetectsViaHtmlLang(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '', htmlLang: 'pl-PL',
        ));

        $result = (new LanguageDetector())->detect($context);

        $this->assertSame('pl-PL', $result['content']['language']['value']);
        $this->assertSame(0.95, $result['content']['language']['confidence']);
    }

    public function testDetectsViaContentLanguageHeader(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['content-language' => ['en']], body: ''));
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));

        $result = (new LanguageDetector())->detect($context);

        $this->assertSame('en', $result['content']['language']['value']);
        $this->assertSame(0.9, $result['content']['language']['confidence']);
    }

    public function testDetectsViaOgLocale(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: ['og:locale' => 'de_DE'], bodyText: '',
        ));

        $result = (new LanguageDetector())->detect($context);

        $this->assertSame('de_DE', $result['content']['language']['value']);
    }

    public function testHtmlLangTakesPrecedence(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: ['content-language' => ['en']], body: ''));
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: ['og:locale' => 'de_DE'], bodyText: '', htmlLang: 'pl',
        ));

        $result = (new LanguageDetector())->detect($context);
        $this->assertSame('pl', $result['content']['language']['value']);
    }

    public function testReturnsNullWhenNoLanguage(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));

        $this->assertNull((new LanguageDetector())->detect($context));
    }
}
