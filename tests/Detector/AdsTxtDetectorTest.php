<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DiscoveryData;
use Scavier\Detector\Marketing\AdsTxtDetector;
use Scavier\Engine\Context;

final class AdsTxtDetectorTest extends TestCase
{
    public function testParsesAdsTxt(): void
    {
        $body = "# Ads.txt\ngoogle.com, pub-1234567890, DIRECT, f08c47fec0942fa0\nappnexus.com, 12345, RESELLER\n";

        $context = new Context();
        $context->set(new DiscoveryData(['/ads.txt' => ['status' => 200, 'body' => $body]]));

        $result = (new AdsTxtDetector())->detect($context);

        $this->assertSame(2, $result['marketing']['ads_txt']['entries']);
        $this->assertContains('Google', $result['marketing']['ads_txt']['exchanges']);
        $this->assertContains('AppNexus/Xandr', $result['marketing']['ads_txt']['exchanges']);
    }

    public function testReturnsNullWhenNoAdsTxt(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/ads.txt' => ['status' => 404, 'body' => null]]));

        $this->assertNull((new AdsTxtDetector())->detect($context));
    }

    public function testReturnsNullForEmptyAdsTxt(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/ads.txt' => ['status' => 200, 'body' => "# Just comments\n"]]));

        $this->assertNull((new AdsTxtDetector())->detect($context));
    }
}
