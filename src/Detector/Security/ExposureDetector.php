<?php

namespace Scavier\Detector\Security;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\Data\DnsZoneTransferData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Collector\DnsZoneTransferCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class ExposureDetector extends Detector
{
    private const SENSITIVE_PATHS = [
        '/.env' => 'Environment file exposed — may contain secrets',
        '/.git/HEAD' => 'Git repository exposed — source code leak',
    ];

    public static function dependencies(): array
    {
        return [DiscoveryCollector::class, DnsZoneTransferCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $exposures = [];

        // File exposure checks
        $discovery = $context->get(DiscoveryData::class);

        if ($discovery !== null) {
            foreach (self::SENSITIVE_PATHS as $path => $description) {
                if ($discovery->exists($path)) {
                    $body = $discovery->body($path);
                    $isReal = $this->validateExposure($path, $body);

                    if ($isReal) {
                        $exposures[] = [
                            'path' => $path,
                            'risk' => 'critical',
                            'description' => $description,
                            'confidence' => 0.95,
                            'evidence' => "HTTP 200 for {$path}",
                        ];
                    }
                }
            }
        }

        // DNS zone transfer vulnerability
        $zoneTransfer = $context->get(DnsZoneTransferData::class);

        if ($zoneTransfer !== null && $zoneTransfer->vulnerable) {
            $hostnames = $zoneTransfer->discoveredHostnames();

            $exposures[] = [
                'path' => 'DNS AXFR',
                'risk' => 'high',
                'description' => 'DNS zone transfer allowed — exposes all DNS records including internal hostnames',
                'confidence' => 1.0,
                'evidence' => 'AXFR succeeded on: ' . implode(', ', $zoneTransfer->vulnerableNameservers),
                'vulnerable_nameservers' => $zoneTransfer->vulnerableNameservers,
                'discovered_records' => count($hostnames),
            ];
        }

        if (empty($exposures)) {
            return null;
        }

        $tags = array_map(fn(array $e) => match ($e['path']) {
            '/.git/HEAD' => 'GitExposed',
            '/.env' => 'EnvExposed',
            'DNS AXFR' => 'DnsZoneTransferVulnerable',
            default => null,
        }, $exposures);

        return [
            'audit' => ['exposures' => $exposures],
            '_tags' => array_values(array_filter($tags)),
        ];
    }

    private function validateExposure(string $path, ?string $body): bool
    {
        if ($body === null) {
            return false;
        }

        return match ($path) {
            '/.env' => (bool) preg_match('/^[A-Z_]+=.*/m', $body) && !preg_match('/<(!DOCTYPE|html|head|body)/i', $body),
            '/.git/HEAD' => str_starts_with($body, 'ref:') || preg_match('/^[0-9a-f]{40}$/', trim($body)),
            default => true,
        };
    }
}
