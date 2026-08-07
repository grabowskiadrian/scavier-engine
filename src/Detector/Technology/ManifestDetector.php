<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class ManifestDetector extends Detector
{
    public static function dependencies(): array
    {
        return [DiscoveryCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $discovery = $context->get(DiscoveryData::class);

        if ($discovery === null) {
            return null;
        }

        $body = null;

        if ($discovery->exists('/manifest.json')) {
            $body = $discovery->body('/manifest.json');
        } elseif ($discovery->exists('/manifest.webmanifest')) {
            $body = $discovery->body('/manifest.webmanifest');
        }

        if ($body === null) {
            return null;
        }

        $manifest = json_decode($body, true);

        if (!is_array($manifest)) {
            return null;
        }

        $result = [
            'is_pwa' => true,
            'confidence' => 0.9,
            'evidence' => 'Web App Manifest found',
        ];

        if (isset($manifest['name'])) {
            $result['name'] = $manifest['name'];
        }

        if (isset($manifest['display'])) {
            $result['display'] = $manifest['display'];
        }

        if (isset($manifest['start_url'])) {
            $result['start_url'] = $manifest['start_url'];
        }

        if (isset($manifest['theme_color'])) {
            $result['theme_color'] = $manifest['theme_color'];
        }

        return ['technology' => ['pwa' => $result], '_tags' => ['PWA']];
    }
}
