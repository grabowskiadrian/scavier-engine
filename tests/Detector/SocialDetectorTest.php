<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Business\SocialDetector;
use Scavier\Engine\Context;

final class SocialDetectorTest extends TestCase
{
    private function context(array $anchors = [], array $jsonLd = [], array $metaProperties = []): Context
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: $metaProperties, bodyText: '',
            anchors: $anchors, jsonLd: $jsonLd,
        ));
        return $context;
    }

    public function testDetectsFacebookViaAnchor(): void
    {
        $result = (new SocialDetector())->detect($this->context(['https://facebook.com/mycompany']));
        $platforms = array_column($result['business']['social'], 'platform');
        $this->assertContains('Facebook', $platforms);
    }

    public function testDetectsLinkedInViaAnchor(): void
    {
        $result = (new SocialDetector())->detect($this->context(['https://linkedin.com/company/acme']));
        $platforms = array_column($result['business']['social'], 'platform');
        $this->assertContains('LinkedIn', $platforms);
    }

    public function testDetectsViaJsonLdSameAs(): void
    {
        $result = (new SocialDetector())->detect($this->context(jsonLd: [
            ['@type' => 'Organization', 'sameAs' => ['https://twitter.com/mycompany', 'https://github.com/mycompany']],
        ]));
        $platforms = array_column($result['business']['social'], 'platform');
        $this->assertContains('Twitter/X', $platforms);
        $this->assertContains('GitHub', $platforms);
    }

    public function testIgnoresShareButtons(): void
    {
        $result = (new SocialDetector())->detect($this->context(['https://facebook.com/sharer/sharer.php?u=example']));
        $this->assertNull($result);
    }

    public function testReturnsNullWhenNoSocial(): void
    {
        $this->assertNull((new SocialDetector())->detect($this->context(['https://example.com'])));
    }
}
