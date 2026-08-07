<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Technology\StructuredDataDetector;
use Scavier\Engine\Context;

final class StructuredDataDetectorTest extends TestCase
{
    public function testDetectsJsonLdTypes(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            jsonLd: [['@type' => 'Organization', 'name' => 'Acme']],
        ));

        $result = (new StructuredDataDetector())->detect($context);

        $this->assertContains('Organization', $result['technology']['structured_data']['types']);
        $this->assertSame(1, $result['technology']['structured_data']['count']);
    }

    public function testHandlesGraphStructure(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            jsonLd: [['@graph' => [['@type' => 'WebPage'], ['@type' => 'WebSite']]]],
        ));

        $result = (new StructuredDataDetector())->detect($context);

        $this->assertContains('WebPage', $result['technology']['structured_data']['types']);
        $this->assertContains('WebSite', $result['technology']['structured_data']['types']);
    }

    public function testReturnsNullWithoutJsonLd(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));

        $this->assertNull((new StructuredDataDetector())->detect($context));
    }
}
