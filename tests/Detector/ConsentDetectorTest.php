<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Marketing\ConsentDetector;
use Scavier\Engine\Context;

final class ConsentDetectorTest extends TestCase
{
    private function context(array $scripts = []): Context
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: $scripts, inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));
        return $context;
    }

    public function testDetectsCookiebot(): void
    {
        $result = (new ConsentDetector())->detect($this->context(['https://consent.cookiebot.com/uc.js']));
        $this->assertSame('Cookiebot', $result['marketing']['consent'][0]['value']);
    }

    public function testDetectsOneTrust(): void
    {
        $result = (new ConsentDetector())->detect($this->context(['https://cdn.cookielaw.org/scripttemplates/otSDKStub.js']));
        $this->assertSame('OneTrust', $result['marketing']['consent'][0]['value']);
    }

    public function testReturnsNullWhenNoConsent(): void
    {
        $this->assertNull((new ConsentDetector())->detect($this->context(['/app.js'])));
    }
}
