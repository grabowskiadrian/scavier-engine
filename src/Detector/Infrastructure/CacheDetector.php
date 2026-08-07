<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HttpCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class CacheDetector extends Detector
{
    public static function dependencies(): array
    {
        return [HttpCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $http = $context->get(HttpData::class);

        if ($http === null) {
            return null;
        }

        $result = [];

        $cacheControl = $http->header('cache-control');
        if ($cacheControl !== null) {
            $result['cache_control'] = $cacheControl;
        }

        $expires = $http->header('expires');
        if ($expires !== null) {
            $result['expires'] = $expires;
        }

        $etag = $http->header('etag');
        if ($etag !== null) {
            $result['etag'] = true;
        }

        $lastModified = $http->header('last-modified');
        if ($lastModified !== null) {
            $result['last_modified'] = $lastModified;
        }

        $age = $http->header('age');
        if ($age !== null) {
            $result['age'] = (int) $age;
        }

        // CDN/proxy cache indicators
        foreach (['x-cache', 'x-cache-hits', 'cf-cache-status', 'x-varnish', 'x-served-by'] as $header) {
            $value = $http->header($header);
            if ($value !== null) {
                $result[str_replace('-', '_', $header)] = $value;
            }
        }

        if (empty($result)) {
            return null;
        }

        $result['confidence'] = 1.0;
        $result['evidence'] = 'HTTP cache headers';

        return ['infrastructure' => ['cache' => $result]];
    }
}
