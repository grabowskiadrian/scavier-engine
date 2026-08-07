<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Marketing\CrmDetector;
use Scavier\Engine\Context;

final class CrmDetectorTest extends TestCase
{
    private function context(array $scripts = [], array $inlineScripts = [], array $cookies = []): Context
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: '', cookies: $cookies));
        $context->set(new HtmlData(
            title: null, meta: [], scripts: $scripts, inlineScripts: $inlineScripts,
            stylesheets: [], metaProperties: [], bodyText: '',
        ));
        return $context;
    }

    public function testDetectsHubSpotViaScript(): void
    {
        $result = (new CrmDetector())->detect($this->context(['https://js.hs-scripts.com/12345.js']));
        $this->assertSame('HubSpot', $result['marketing']['crm'][0]['value']);
    }

    public function testDetectsHubSpotViaCookie(): void
    {
        $result = (new CrmDetector())->detect($this->context(cookies: ['hubspotutk' => 'abc']));
        $this->assertSame('HubSpot', $result['marketing']['crm'][0]['value']);
    }

    public function testDetectsMarketoViaInline(): void
    {
        $result = (new CrmDetector())->detect($this->context(inlineScripts: ['Munchkin.init("123-ABC-456")']));
        $this->assertSame('Marketo', $result['marketing']['crm'][0]['value']);
    }

    public function testDetectsKlaviyo(): void
    {
        $result = (new CrmDetector())->detect($this->context(['https://static.klaviyo.com/onsite/js/klaviyo.js']));
        $this->assertSame('Klaviyo', $result['marketing']['crm'][0]['value']);
    }

    public function testReturnsNullWhenNoCrm(): void
    {
        $this->assertNull((new CrmDetector())->detect($this->context(['/app.js'])));
    }
}
