<?php

namespace Scavier\Detector\Security;

use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HttpCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class CookieDetector extends Detector
{
    private const KNOWN_TRACKERS = [
        '_ga' => 'Google Analytics',
        '_gid' => 'Google Analytics',
        '_gat' => 'Google Analytics',
        '_fbp' => 'Facebook Pixel',
        '_fbc' => 'Facebook Pixel',
        '_gcl_au' => 'Google Ads',
        '_gcl_aw' => 'Google Ads',
        '_uetsid' => 'Microsoft Ads',
        '_uetvid' => 'Microsoft Ads',
        '_hjid' => 'Hotjar',
        '_hjSessionUser' => 'Hotjar',
        'hubspotutk' => 'HubSpot',
        '__hssc' => 'HubSpot',
        '__hstc' => 'HubSpot',
        '__hssrc' => 'HubSpot',
    ];

    public static function dependencies(): array
    {
        return [HttpCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $http = $context->get(HttpData::class);

        if ($http === null || empty($http->cookies)) {
            return null;
        }

        $cookies = [];
        $trackers = [];

        foreach ($http->cookies as $name => $value) {
            $entry = ['name' => $name];

            if (isset(self::KNOWN_TRACKERS[$name])) {
                $entry['tracker'] = self::KNOWN_TRACKERS[$name];
                $trackers[] = self::KNOWN_TRACKERS[$name];
            }

            $cookies[] = $entry;
        }

        // Parse Set-Cookie headers for attributes
        $attributes = [];
        foreach ($http->headerAll('set-cookie') as $raw) {
            $parts = explode(';', $raw);
            $nameVal = explode('=', trim($parts[0]), 2);
            $cookieName = trim($nameVal[0]);
            $flags = [];

            foreach (array_slice($parts, 1) as $part) {
                $kv = explode('=', trim($part), 2);
                $flag = strtolower(trim($kv[0]));
                if ($flag === 'samesite') {
                    $flags[] = 'samesite=' . strtolower(trim($kv[1] ?? 'lax'));
                } elseif (in_array($flag, ['secure', 'httponly'])) {
                    $flags[] = $flag;
                }
            }

            if (!empty($flags)) {
                $attributes[$cookieName] = $flags;
            }
        }

        $uniqueTrackers = array_values(array_unique($trackers));

        return [
            'security' => [
                'cookies' => [
                    'count' => count($cookies),
                    'cookies' => $cookies,
                    'trackers' => $uniqueTrackers,
                    'attributes' => $attributes,
                    'confidence' => 1.0,
                    'evidence' => 'HTTP Set-Cookie headers',
                ],
            ],
            '_tags' => $uniqueTrackers,
        ];
    }
}
