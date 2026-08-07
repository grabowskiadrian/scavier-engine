<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\DnsCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class MailProviderDetector extends Detector
{
    private const PATTERNS = [
        'Google Workspace' => '/google\.com$|googlemail\.com$/i',
        'Microsoft 365' => '/outlook\.com$|protection\.outlook\.com$/i',
        'Zoho Mail' => '/zoho\.com$/i',
        'ProtonMail' => '/protonmail\.ch$/i',
        'OVH' => '/ovh\.(net|com)$/i',
        'Yandex Mail' => '/yandex\.(net|ru)$/i',
        'MXRoute' => '/mxrouting\.net$/i',
        'Fastmail' => '/fastmail\.com$|messagingengine\.com$/i',
        'Amazon SES' => '/amazonaws\.com$/i',
        'Mailgun' => '/mailgun\.(org|com|net)$/i',
        'SendGrid' => '/sendgrid\.net$/i',
        'Postmark' => '/mtasv\.net$/i',
    ];

    public static function dependencies(): array
    {
        return [DnsCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $dns = $context->get(DnsData::class);

        if ($dns === null || empty($dns->mx)) {
            return null;
        }

        $exchangers = $dns->mailExchangers();
        $providers = [];
        $found = [];

        foreach ($exchangers as $mx) {
            foreach (self::PATTERNS as $provider => $pattern) {
                if (!isset($found[$provider]) && preg_match($pattern, $mx)) {
                    $found[$provider] = true;
                    $providers[] = [
                        'value' => $provider,
                        'confidence' => 0.95,
                        'evidence' => "MX record: {$mx}",
                    ];
                }
            }
        }

        if (empty($providers)) {
            // Unknown provider — still report the MX records
            $providers[] = [
                'value' => 'Unknown',
                'confidence' => 0.5,
                'evidence' => 'MX: ' . implode(', ', array_slice($exchangers, 0, 3)),
            ];
        }

        $tags = array_values(array_filter(array_column($providers, 'value'), fn($v) => $v !== 'Unknown'));

        return ['infrastructure' => ['mail' => $providers], '_tags' => $tags];
    }
}
