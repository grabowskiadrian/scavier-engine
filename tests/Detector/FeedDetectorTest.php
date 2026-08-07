<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Content\FeedDetector;
use Scavier\Engine\Context;

final class FeedDetectorTest extends TestCase
{
    public function testDetectsRssFeed(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            links: [['rel' => 'alternate', 'href' => 'https://example.com/feed/rss']],
        ));

        $result = (new FeedDetector())->detect($context);

        $this->assertSame('RSS', $result['content']['feeds'][0]['type']);
        $this->assertSame('https://example.com/feed/rss', $result['content']['feeds'][0]['url']);
    }

    public function testDetectsAtomFeed(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            links: [['rel' => 'alternate', 'href' => '/feed/atom.xml']],
        ));

        $result = (new FeedDetector())->detect($context);

        $this->assertSame('Atom', $result['content']['feeds'][0]['type']);
    }

    public function testReturnsNullWhenNoFeeds(): void
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: null, meta: [], scripts: [], inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
            links: [['rel' => 'stylesheet', 'href' => '/style.css']],
        ));

        $this->assertNull((new FeedDetector())->detect($context));
    }
}
