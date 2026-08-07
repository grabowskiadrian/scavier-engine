<?php

namespace Scavier\Detector\Content;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class FeedDetector extends Detector
{
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

        $feeds = [];

        foreach ($html->links as $link) {
            if ($link['rel'] !== 'alternate') {
                continue;
            }

            $href = $link['href'];

            // Check URL patterns for feed types
            if (preg_match('/\.(rss|atom|xml)$/i', $href) || preg_match('/\/(feed|rss|atom)\/?$/i', $href)) {
                $type = 'RSS/Atom';

                if (preg_match('/atom/i', $href)) {
                    $type = 'Atom';
                } elseif (preg_match('/rss/i', $href)) {
                    $type = 'RSS';
                }

                $feeds[] = [
                    'type' => $type,
                    'url' => $href,
                    'confidence' => 0.9,
                    'evidence' => 'link[rel=alternate]',
                ];
            }
        }

        if (empty($feeds)) {
            return null;
        }

        return ['content' => ['feeds' => $feeds]];
    }
}
