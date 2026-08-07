<?php

namespace Scavier\Detector\Security;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class SecurityTxtDetector extends Detector
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

        if (!$discovery->exists('/.well-known/security.txt')) {
            return null;
        }

        $body = $discovery->body('/.well-known/security.txt');

        $result = [
            'exists' => true,
            'confidence' => 1.0,
            'evidence' => '/.well-known/security.txt found',
        ];

        if ($body !== null) {
            $fields = [];

            foreach (explode("\n", $body) as $line) {
                $line = trim($line);

                if ($line === '' || str_starts_with($line, '#')) {
                    continue;
                }

                if (preg_match('/^(Contact|Expires|Encryption|Acknowledgments|Preferred-Languages|Canonical|Policy|Hiring):\s*(.+)/i', $line, $m)) {
                    $key = strtolower($m[1]);
                    $fields[$key][] = trim($m[2]);
                }
            }

            $result['fields'] = $fields;
        }

        return ['security' => ['security_txt' => $result]];
    }
}
