<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Marketing\ChatDetector;
use Scavier\Engine\Context;

final class ChatDetectorTest extends TestCase
{
    private function context(array $scripts = [], array $inlineScripts = []): Context
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: $scripts, inlineScripts: $inlineScripts,
            stylesheets: [], metaProperties: [], bodyText: '',
        ));
        return $context;
    }

    public function testDetectsIntercom(): void
    {
        $result = (new ChatDetector())->detect($this->context(['https://widget.intercom.io/widget/abc123']));
        $this->assertSame('Intercom', $result['marketing']['chat'][0]['value']);
    }

    public function testDetectsTawkTo(): void
    {
        $result = (new ChatDetector())->detect($this->context(['https://embed.tawk.to/123/default']));
        $this->assertSame('Tawk.to', $result['marketing']['chat'][0]['value']);
    }

    public function testDetectsCrispViaInline(): void
    {
        $result = (new ChatDetector())->detect($this->context(inlineScripts: ['window.$crisp=[];CRISP_WEBSITE_ID="abc";(function(){d=document;s=d.createElement("script");s.src="https://client.crisp.chat/l.js"'])
        );
        $this->assertSame('Crisp', $result['marketing']['chat'][0]['value']);
    }

    public function testReturnsNullWhenNoChat(): void
    {
        $this->assertNull((new ChatDetector())->detect($this->context(['/app.js'])));
    }
}
