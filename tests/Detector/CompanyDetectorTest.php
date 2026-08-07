<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Business\CompanyDetector;
use Scavier\Engine\Context;

final class CompanyDetectorTest extends TestCase
{
    public function testExtractsFromJsonLd(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            jsonLd: [[
                '@type' => 'Organization',
                'name' => 'Acme Corp',
                'url' => 'https://acme.com',
                'logo' => 'https://acme.com/logo.png',
                'description' => 'We make things',
                'foundingDate' => '2020-01-01',
            ]],
        ));

        $result = (new CompanyDetector())->detect($context);

        $this->assertSame('Acme Corp', $result['business']['company']['name']['value']);
        $this->assertSame(0.95, $result['business']['company']['name']['confidence']);
        $this->assertSame('https://acme.com', $result['business']['company']['url']);
        $this->assertSame('https://acme.com/logo.png', $result['business']['company']['logo']);
    }

    public function testFallsBackToOgSiteName(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: ['og:site_name' => 'My Company'], bodyText: '',
        ));

        $result = (new CompanyDetector())->detect($context);

        $this->assertSame('My Company', $result['business']['company']['name']['value']);
        $this->assertSame(0.7, $result['business']['company']['name']['confidence']);
    }

    public function testJsonLdTakesPrecedenceOverOg(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: ['og:site_name' => 'OG Name'], bodyText: '',
            jsonLd: [['@type' => 'Organization', 'name' => 'JSON-LD Name']],
        ));

        $result = (new CompanyDetector())->detect($context);

        $this->assertSame('JSON-LD Name', $result['business']['company']['name']['value']);
    }

    public function testReturnsNullWhenNoCompanyData(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));

        $this->assertNull((new CompanyDetector())->detect($context));
    }
}
