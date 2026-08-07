<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Technology\CmsDetector;
use Scavier\Engine\Context;

final class CmsDetectorTest extends TestCase
{
    private function context(array $meta = [], string $body = '', array $cookies = []): Context
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: $body, cookies: $cookies));
        $context->set(new HtmlData(
            title: null, meta: $meta, scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));
        return $context;
    }

    public function testDetectsWordPressViaGenerator(): void
    {
        $result = (new CmsDetector())->detect($this->context(['generator' => 'WordPress 6.5']));
        $this->assertSame('WordPress', $result['technology']['cms']['value']);
        $this->assertGreaterThanOrEqual(0.9, $result['technology']['cms']['confidence']);
    }

    public function testDetectsWordPressViaHtmlPattern(): void
    {
        $result = (new CmsDetector())->detect($this->context(body: '<link href="/wp-content/themes/style.css">'));
        $this->assertSame('WordPress', $result['technology']['cms']['value']);
    }

    public function testDetectsWordPressViaCookie(): void
    {
        $result = (new CmsDetector())->detect($this->context(cookies: ['wordpress_logged_in_abc' => '1']));
        $this->assertSame('WordPress', $result['technology']['cms']['value']);
    }

    public function testDetectsDrupalViaGenerator(): void
    {
        $result = (new CmsDetector())->detect($this->context(['generator' => 'Drupal 10']));
        $this->assertSame('Drupal', $result['technology']['cms']['value']);
    }

    public function testDetectsSquarespaceViaHtmlPattern(): void
    {
        $result = (new CmsDetector())->detect($this->context(body: '<script src="https://static.squarespace.com/assets/v1/site.js">'));
        $this->assertSame('Squarespace', $result['technology']['cms']['value']);
    }

    public function testReturnsNullWhenNoCms(): void
    {
        $this->assertNull((new CmsDetector())->detect($this->context()));
    }

    public function testMultipleSignalsIncreaseConfidence(): void
    {
        $result = (new CmsDetector())->detect($this->context(
            ['generator' => 'WordPress 6.5'],
            '<link href="/wp-content/themes/style.css">',
            ['wordpress_logged_in' => '1'],
        ));
        $this->assertSame('WordPress', $result['technology']['cms']['value']);
        $this->assertGreaterThan(0.95, $result['technology']['cms']['confidence']);
    }
}
