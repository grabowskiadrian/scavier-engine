<?php

namespace Scavier\Detector\Security;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\DnsCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class DnsSecurityDetector extends Detector
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

        $result = [
            'dnssec' => [
                'configured' => $dns->hasDnssec(),
                'confidence' => 1.0,
                'evidence' => $dns->hasDnssec()
                    ? 'DNSKEY record found'
                    : 'No DNSKEY record — DNS responses not authenticated',
            ],
            'caa' => [
                'configured' => $dns->hasCaa(),
                'issuers' => $dns->caaIssuers(),
                'confidence' => 1.0,
                'evidence' => $dns->hasCaa()
                    ? 'CAA records: ' . implode(', ', $dns->caaIssuers())
                    : 'No CAA records — any CA can issue certificates',
            ],
        ];

        if ($dns->hasTlsa()) {
            $result['dane'] = [
                'configured' => true,
                'records' => count($dns->tlsa),
                'confidence' => 1.0,
                'evidence' => 'TLSA records found for _443._tcp',
            ];
        }

        return ['domain' => ['dns_security' => $result]];
    }
}
