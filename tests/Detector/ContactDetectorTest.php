<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Business\ContactDetector;
use Scavier\Engine\Context;

final class ContactDetectorTest extends TestCase
{
    public function testExtractsFromJsonLd(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            jsonLd: [[
                '@type' => 'Organization',
                'email' => 'info@example.com',
                'telephone' => '+48 123 456 789',
                'address' => [
                    '@type' => 'PostalAddress',
                    'streetAddress' => 'ul. Testowa 1',
                    'postalCode' => '00-001',
                    'addressLocality' => 'Warszawa',
                    'addressCountry' => 'PL',
                ],
            ]],
        ));

        $result = (new ContactDetector())->detect($context);

        $this->assertSame('info@example.com', $result['business']['contacts']['emails'][0]['value']);
        $this->assertSame('+48 123 456 789', $result['business']['contacts']['phones'][0]['value']);
        $this->assertStringContainsString('Warszawa', $result['business']['contacts']['address']['value']);
    }

    public function testExtractsContactPoint(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            jsonLd: [[
                '@type' => 'Organization',
                'contactPoint' => ['@type' => 'ContactPoint', 'telephone' => '+1-800-555-0199'],
            ]],
        ));

        $result = (new ContactDetector())->detect($context);

        $this->assertSame('+1-800-555-0199', $result['business']['contacts']['phones'][0]['value']);
    }

    public function testReturnsNullWhenNoContacts(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));

        $this->assertNull((new ContactDetector())->detect($context));
    }
}
