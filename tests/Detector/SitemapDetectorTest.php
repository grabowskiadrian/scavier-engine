<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DiscoveryData;
use Scavier\Detector\Seo\SitemapDetector;
use Scavier\Engine\Context;

final class SitemapDetectorTest extends TestCase
{
    public function testDetectsSitemap(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/sitemap.xml' => [
            'status' => 200,
            'body' => '<?xml version="1.0"?><urlset><url><loc>https://example.com/</loc></url><url><loc>https://example.com/about</loc></url></urlset>',
        ]]));

        $result = (new SitemapDetector())->detect($context);

        $this->assertTrue($result['seo']['sitemap']['exists']);
        $this->assertFalse($result['seo']['sitemap']['is_index']);
        $this->assertSame(2, $result['seo']['sitemap']['url_count']);
    }

    public function testDetectsSitemapIndex(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/sitemap.xml' => [
            'status' => 200,
            'body' => '<?xml version="1.0"?><sitemapindex><sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap><sitemap><loc>https://example.com/sitemap-2.xml</loc></sitemap></sitemapindex>',
        ]]));

        $result = (new SitemapDetector())->detect($context);

        $this->assertTrue($result['seo']['sitemap']['is_index']);
        $this->assertSame(2, $result['seo']['sitemap']['sitemap_count']);
    }

    public function testReportsMissingSitemap(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/sitemap.xml' => ['status' => 404, 'body' => null]]));

        $result = (new SitemapDetector())->detect($context);

        $this->assertFalse($result['seo']['sitemap']['exists']);
    }
}
