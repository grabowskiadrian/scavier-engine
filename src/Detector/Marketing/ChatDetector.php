<?php

namespace Scavier\Detector\Marketing;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class ChatDetector extends Detector
{
    private const SCRIPT_PATTERNS = [
        'Intercom' => '/widget\.intercom\.io|intercomcdn\.com/i',
        'Drift' => '/drift\.com|driftt\.com/i',
        'Zendesk' => '/static\.zdassets\.com|zopim\.com/i',
        'Crisp' => '/client\.crisp\.chat/i',
        'Tawk.to' => '/embed\.tawk\.to/i',
        'LiveChat' => '/cdn\.livechatinc\.com/i',
        'HubSpot Chat' => '/js\.usemessages\.com|js\.hubspot\.com/i',
        'Tidio' => '/code\.tidio\.co/i',
        'Freshchat' => '/wchat\.freshchat\.com/i',
        'Olark' => '/static\.olark\.com/i',
        'Chatwoot' => '/chatwoot/i',
    ];

    public static function dependencies(): array
    {
        return [HtmlCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $html = $context->get(HtmlData::class);

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

        // Inline script patterns
        foreach (self::SCRIPT_PATTERNS as $name => $pattern) {
            if (!isset($found[$name]) && $html->hasInlineScriptMatching($pattern)) {
                $found[$name] = true;
                $results[] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => 'Inline script pattern',
                ];
            }
        }

        if (empty($results)) {
            return null;
        }

        $tags = array_column($results, 'value');

        return ['marketing' => ['chat' => $results], '_tags' => $tags];
    }
}
