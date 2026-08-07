<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\DnsCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class Ipv6Detector extends Detector
{
    public static function dependencies(): array
    {
        return [DnsCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $dns = $context->get(DnsData::class);

        if ($dns === null) {
            return null;
        }

        $hasIpv4 = !empty($dns->a);
        $hasIpv6 = !empty($dns->aaaa);

        $stack = match (true) {
            $hasIpv4 && $hasIpv6 => 'dual-stack',
            $hasIpv6 => 'ipv6-only',
            $hasIpv4 => 'ipv4-only',
            default => null,
        };

        if ($stack === null) {
            return null;
        }

        return [
            'infrastructure' => [
                'ip' => [
                    'stack' => $stack,
                    'ipv4' => $hasIpv4,
                    'ipv6' => $hasIpv6,
                    'confidence' => 1.0,
                    'evidence' => 'DNS A/AAAA records',
                ],
            ]
        ];
    }
}
