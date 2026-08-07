<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DiscoveryData;
use Scavier\Detector\Technology\ManifestDetector;
use Scavier\Engine\Context;

final class ManifestDetectorTest extends TestCase
{
    public function testDetectsPwa(): void
    {
        $manifest = json_encode([
            'name' => 'My App',
            'display' => 'standalone',
            'start_url' => '/',
            'theme_color' => '#ffffff',
        ]);

        $context = new Context();
        $context->set(new DiscoveryData(['/manifest.json' => ['status' => 200, 'body' => $manifest]]));

        $result = (new ManifestDetector())->detect($context);

        $this->assertTrue($result['technology']['pwa']['is_pwa']);
        $this->assertSame('My App', $result['technology']['pwa']['name']);
        $this->assertSame('standalone', $result['technology']['pwa']['display']);
    }

    public function testDetectsWebmanifest(): void
    {
        $manifest = json_encode(['name' => 'App', 'display' => 'fullscreen']);

        $context = new Context();
        $context->set(new DiscoveryData([
            '/manifest.json' => ['status' => 404, 'body' => null],
            '/manifest.webmanifest' => ['status' => 200, 'body' => $manifest],
        ]));

        $result = (new ManifestDetector())->detect($context);

        $this->assertSame('App', $result['technology']['pwa']['name']);
    }

    public function testReturnsNullWhenNoManifest(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData([
            '/manifest.json' => ['status' => 404, 'body' => null],
            '/manifest.webmanifest' => ['status' => 404, 'body' => null],
        ]));

        $this->assertNull((new ManifestDetector())->detect($context));
    }
}
