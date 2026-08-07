<?php

namespace Scavier\Detector\Security;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\DnsCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class EmailSecurityDetector extends Detector
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

        $txtValues = $dns->txtValues();
        $result = [];

        // SPF
        $spf = null;
        foreach ($txtValues as $txt) {
            if (str_starts_with(strtolower($txt), 'v=spf1')) {
                $spf = $txt;
                break;
            }
        }

        $result['spf'] = [
            'configured' => $spf !== null,
            'value' => $spf,
            'confidence' => 1.0,
            'evidence' => $spf !== null ? "TXT record: {$spf}" : 'No SPF TXT record found',
        ];

        // DMARC (queried from _dmarc.domain, included in DnsCollector's mergeTxt)
        $dmarc = null;
        foreach ($txtValues as $txt) {
            if (str_starts_with(strtolower($txt), 'v=dmarc1')) {
                $dmarc = $txt;
                break;
            }
        }

        $result['dmarc'] = [
            'configured' => $dmarc !== null,
            'value' => $dmarc,
            'confidence' => 1.0,
            'evidence' => $dmarc !== null ? "TXT record: {$dmarc}" : 'No DMARC TXT record found',
        ];

        // DMARC policy extraction
        if ($dmarc !== null && preg_match('/p=(none|quarantine|reject)/i', $dmarc, $m)) {
            $result['dmarc']['policy'] = strtolower($m[1]);
        }

        return ['security' => ['email' => $result]];
    }
}
