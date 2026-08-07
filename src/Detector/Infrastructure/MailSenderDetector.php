<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\DnsCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

/**
 * Detects email sending services from SPF includes.
 *
 * Different from MailProviderDetector (MX = who hosts the mailbox).
 * This detects who SENDS emails on behalf of the domain — newsletters,
 * transactional emails, marketing automation.
 */
class MailSenderDetector extends Detector
{
    private const SPF_PATTERNS = [
        // Marketing automation
        'MailerLite' => '/mlsend\.com|mailerlite/i',
        'Mailchimp' => '/mandrillapp\.com|mcsv\.net|mailchimp/i',
        'SendGrid' => '/sendgrid\.net/i',
        'GetResponse' => '/getresponse\.com|getresponse\.pl/i',
        'ActiveCampaign' => '/activecampaign\.com/i',
        'Brevo' => '/sendinblue\.com|brevo\.com/i',
        'Klaviyo' => '/klaviyo\.com/i',
        'ConvertKit' => '/convertkit\.com/i',
        'Omnisend' => '/omnisend\.com/i',
        'Campaign Monitor' => '/cmail\d+\.com|createsend/i',
        'Constant Contact' => '/constantcontact\.com/i',
        'HubSpot' => '/hubspot\.com|hubspotemail/i',

        // Transactional
        'Amazon SES' => '/amazonses\.com/i',
        'Postmark' => '/mtasv\.net|postmarkapp/i',
        'Mailgun' => '/mailgun\.org/i',
        'SparkPost' => '/sparkpostmail\.com/i',

        // Workspace (may also appear in SPF)
        'Google Workspace' => '/_spf\.google\.com|googlemail\.com/i',
        'Microsoft 365' => '/protection\.outlook\.com|outlook\.com/i',
        'Zoho' => '/zoho\.(com|eu)/i',
    ];

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

        // Find SPF record
        $spf = null;
        foreach ($dns->txtValues() as $txt) {
            if (str_starts_with(strtolower($txt), 'v=spf1')) {
                $spf = $txt;
                break;
            }
        }

        if ($spf === null) {
            return null;
        }

        $senders = [];
        $found = [];

        foreach (self::SPF_PATTERNS as $name => $pattern) {
            if (!isset($found[$name]) && preg_match($pattern, $spf)) {
                $found[$name] = true;

                // Extract the matching include directive from SPF
                $evidence = "SPF record match";
                if (preg_match_all('/include:(\S+)/i', $spf, $allIncludes)) {
                    foreach ($allIncludes[1] as $inc) {
                        if (preg_match($pattern, $inc)) {
                            $evidence = "SPF include: {$inc}";
                            break;
                        }
                    }
                }

                $senders[] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => $evidence,
                ];
            }
        }

        if ($senders === []) {
            return null;
        }

        $tags = array_column($senders, 'value');

        return ['infrastructure' => ['mail_senders' => $senders], '_tags' => $tags];
    }
}
