<?php

namespace Scavier\Detector\Seo;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class RobotsDetector extends Detector
{
    private const AI_BOTS = [
        'GPTBot',
        'ChatGPT-User',
        'Google-Extended',
        'CCBot',
        'anthropic-ai',
        'ClaudeBot',
        'Claude-Web',
        'Bytespider',
        'Diffbot',
        'FacebookBot',
        'PerplexityBot',
        'Cohere-ai',
    ];

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

        $exists = $discovery->exists('/robots.txt');
        $body = $discovery->body('/robots.txt');

        $result = [
            'exists' => $exists,
            'confidence' => 1.0,
            'evidence' => $exists ? 'robots.txt found' : 'robots.txt not found or returned error',
        ];

        if ($exists && $body !== null) {
            $rules = [];
            $sitemaps = [];
            $currentAgent = '*';
            $blockedBots = [];
            $blocksAll = false;

            foreach (explode("\n", $body) as $line) {
                $line = trim($line);

                if ($line === '' || str_starts_with($line, '#')) {
                    continue;
                }

                if (preg_match('/^User-agent:\s*(.+)/i', $line, $m)) {
                    $currentAgent = trim($m[1]);
                    $rules[] = ['directive' => 'User-agent', 'value' => $currentAgent];
                } elseif (preg_match('/^Sitemap:\s*(.+)/i', $line, $m)) {
                    $sitemaps[] = trim($m[1]);
                } elseif (preg_match('/^(Disallow|Allow|Crawl-delay):\s*(.*)/i', $line, $m)) {
                    $directive = $m[1];
                    $value = trim($m[2]);
                    $rules[] = ['directive' => $directive, 'value' => $value];

                    // Detect full block
                    if (strtolower($directive) === 'disallow' && $value === '/') {
                        if ($currentAgent === '*') {
                            $blocksAll = true;
                        }

                        // Check if this is an AI bot being blocked
                        foreach (self::AI_BOTS as $bot) {
                            if (strcasecmp($currentAgent, $bot) === 0) {
                                $blockedBots[] = $bot;
                            }
                        }
                    }
                }
            }

            $result['rules_count'] = count($rules);
            $result['sitemaps'] = $sitemaps;
            $result['blocks_all_crawlers'] = $blocksAll;

            // AI bot blocking analysis
            $aiBots = [
                'blocked' => array_values(array_unique($blockedBots)),
                'blocks_ai_crawlers' => !empty($blockedBots) || $blocksAll,
            ];

            if (!empty($blockedBots)) {
                $aiBots['count'] = count(array_unique($blockedBots));
            }

            $result['ai_bots'] = $aiBots;
        }

        return ['seo' => ['robots' => $result]];
    }
}
