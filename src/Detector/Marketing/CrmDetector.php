<?php

namespace Scavier\Detector\Marketing;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class CrmDetector extends Detector
{
    private const SCRIPT_PATTERNS = [
        'HubSpot' => '/js\.hs-scripts\.com|js\.hubspot\.com|js\.usemessages\.com|js\.hs-banner\.com/i',
        'Salesforce Pardot' => '/pi\.pardot\.com|pardot\.com\/pd\.js/i',
        'Marketo' => '/munchkin\.marketo\.net|marketo\.com/i',
        'ActiveCampaign' => '/trackcmp\.net|activehosted\.com/i',
        'Pipedrive' => '/leadbooster-chat\.pipedrive\.com/i',
        'Freshsales' => '/freshsales\.io/i',
        'Zoho CRM' => '/salesiq\.zoho\.(com|eu)/i',
        'Keap (Infusionsoft)' => '/infusionsoft\.app|keap\.com/i',
        'Drip' => '/getdrip\.com|dc\.js/i',
        'Klaviyo' => '/static\.klaviyo\.com/i',
        'Mailchimp' => '/chimpstatic\.com|list-manage\.com/i',
        'Brevo (Sendinblue)' => '/sibautomation\.com|sendinblue\.com/i',
        'GetResponse' => '/getresponse\.com|gr-widget/i',
        'MailerLite' => '/mailerlite\.com|ml\.js/i',
        'ConvertKit' => '/convertkit\.com|ck\.js/i',
        'Omnisend' => '/omnisend\.com|omnisrc/i',
    ];

    private const COOKIE_PATTERNS = [
        'HubSpot' => '/^(hubspotutk|__hs|__hstc|__hssc|__hssrc)$/i',
        'Marketo' => '/^_mkto_trk$/i',
        'ActiveCampaign' => '/^_actc$/i',
        'Pardot' => '/^pardot$/i',
    ];

    private const INLINE_PATTERNS = [
        'HubSpot' => '/hbspt\.forms\.create|HubSpotConversations/i',
        'Marketo' => '/MktoForms2|Munchkin\.init/i',
        'ActiveCampaign' => '/trackcmp_email/i',
        'Klaviyo' => '/klaviyo\.push/i',
    ];

    public static function dependencies(): array
    {
        return [HtmlCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $html = $context->get(HtmlData::class);
        $http = $context->get(HttpData::class);

        if ($html === null) {
            return null;
        }

        $results = [];
        $found = [];

        // Script URLs
        foreach (self::SCRIPT_PATTERNS as $name => $pattern) {
            $matches = $html->scriptsMatching($pattern);
            if (!empty($matches) && !isset($found[$name])) {
                $found[$name] = true;
                $results[] = [
                    'value' => $name,
                    'confidence' => 0.9,
                    'evidence' => 'Script src: ' . $matches[0],
                ];
            }
        }

        // Inline scripts
        foreach (self::INLINE_PATTERNS as $name => $pattern) {
            if (!isset($found[$name]) && $html->hasInlineScriptMatching($pattern)) {
                $found[$name] = true;
                $results[] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => 'Inline script pattern',
                ];
            }
        }

        // Cookies
        if ($http !== null) {
            foreach (self::COOKIE_PATTERNS as $name => $pattern) {
                if (!isset($found[$name])) {
                    foreach (array_keys($http->cookies) as $cookieName) {
                        if (preg_match($pattern, $cookieName)) {
                            $found[$name] = true;
                            $results[] = [
                                'value' => $name,
                                'confidence' => 0.9,
                                'evidence' => "Cookie: {$cookieName}",
                            ];
                            break;
                        }
                    }
                }
            }
        }

        if (empty($results)) {
            return null;
        }

        $tags = array_column($results, 'value');

        return ['marketing' => ['crm' => $results], '_tags' => $tags];
    }
}
