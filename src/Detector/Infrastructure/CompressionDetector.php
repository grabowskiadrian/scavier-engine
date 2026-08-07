<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HttpCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class CompressionDetector extends Detector
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

        $encoding = $http->header('content-encoding');

        return [
            'infrastructure' => [
                'compression' => [
                    'enabled' => $encoding !== null,
                    'algorithm' => $encoding,
                    'confidence' => 1.0,
                    'evidence' => $encoding !== null
                        ? "Content-Encoding: {$encoding}"
                        : 'No Content-Encoding header',
                ],
            ]
        ];
    }
}
