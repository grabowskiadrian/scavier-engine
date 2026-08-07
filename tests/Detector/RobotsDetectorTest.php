<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DiscoveryData;
use Scavier\Detector\Seo\RobotsDetector;
use Scavier\Engine\Context;

final class RobotsDetectorTest extends TestCase
{
    public function testDetectsRobotsTxt(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/robots.txt' => [
            'status' => 200,
            'body' => "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml",
        ]]));

        $result = (new RobotsDetector())->detect($context);

        $this->assertTrue($result['seo']['robots']['exists']);
        $this->assertSame(2, $result['seo']['robots']['rules_count']);
        $this->assertSame(['https://example.com/sitemap.xml'], $result['seo']['robots']['sitemaps']);
    }

    public function testReportsMissingRobotsTxt(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/robots.txt' => ['status' => 404, 'body' => null]]));

        $result = (new RobotsDetector())->detect($context);

        $this->assertFalse($result['seo']['robots']['exists']);
    }
}
