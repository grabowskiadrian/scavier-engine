<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

/**
 * Detects strategic SaaS/app signals: authentication providers, search engines,
 * push notification services. Each signal says something about the business:
 * - Auth provider = building a SaaS/app with user accounts
 * - Search engine = large content catalog
 * - Push notifications = investing in user retention
 * - Error monitoring = ops maturity
 * - Feature flags = engineering maturity
 * - Headless CMS = modern architecture
 */
class SaasSignalDetector extends Detector
{
    private const AUTH_PATTERNS = [
        'Auth0' => '/cdn\.auth0\.com|auth0\.js/i',
        'Okta' => '/ok\d+\.(okta|oktapreview)\.com/i',
        'Firebase Auth' => '/firebase(app)?\.js|firebaseauth/i',
        'Clerk' => '/clerk\.com|clerk\.js/i',
        'Supabase Auth' => '/supabase\.co.*auth|supabase\.js/i',
    ];

    private const SEARCH_PATTERNS = [
        'Algolia' => '/algoliasearch|algolia\.net|algoliacdn/i',
        'Doofinder' => '/doofinder\.com/i',
        'Meilisearch' => '/meilisearch/i',
        'Elasticsearch' => '/elasticsearch|elastic\.co/i',
        'Typesense' => '/typesense/i',
    ];

    private const PUSH_PATTERNS = [
        'OneSignal' => '/onesignal\.com/i',
        'PushEngage' => '/pushengage\.com|clientcdn\.pushengage/i',
        'WebPushr' => '/webpushr\.com/i',
        'Pushwoosh' => '/pushwoosh\.com/i',
    ];

    private const MONITORING_PATTERNS = [
        'Sentry' => '/sentry\.io|browser\.sentry-cdn/i',
        'Datadog' => '/datadoghq\.com|dd-rum/i',
        'New Relic' => '/newrelic\.com|nr-data\.net|NREUM/i',
        'Bugsnag' => '/bugsnag\.com|bugsnag\.js/i',
        'Rollbar' => '/rollbar\.com|rollbar\.js/i',
    ];

    private const FEATURE_FLAG_PATTERNS = [
        'LaunchDarkly' => '/launchdarkly\.com|ld-cdn/i',
        'Unleash' => '/unleash\.io|getunleash/i',
        'Flagsmith' => '/flagsmith\.com/i',
        'Statsig' => '/statsig\.com|statsig\.js/i',
    ];

    private const HEADLESS_CMS_PATTERNS = [
        'Contentful' => '/contentful\.com|ctfassets\.net/i',
        'Strapi' => '/strapi\.io/i',
        'Sanity' => '/sanity\.io|cdn\.sanity/i',
        'Prismic' => '/prismic\.io|cdn\.prismic/i',
        'Storyblok' => '/storyblok\.com/i',
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

        $signals = [];

        $allSources = array_merge($html->scripts, $html->stylesheets);
        $allContent = implode("\n", $allSources) . "\n" . implode("\n", $html->inlineScripts);

        // Auth providers (= building app/SaaS)
        foreach (self::AUTH_PATTERNS as $name => $pattern) {
            if ($this->matchSources($allContent, $allSources, $pattern)) {
                $signals['auth'] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => "Script pattern: {$name}",
                ];
                break;
            }
        }

        // Search engines (= large catalog/content)
        foreach (self::SEARCH_PATTERNS as $name => $pattern) {
            if ($this->matchSources($allContent, $allSources, $pattern)) {
                $signals['search'] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => "Script pattern: {$name}",
                ];
                break;
            }
        }

        // Push notifications (= user retention)
        foreach (self::PUSH_PATTERNS as $name => $pattern) {
            if ($this->matchSources($allContent, $allSources, $pattern)) {
                $signals['push_notifications'] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => "Script pattern: {$name}",
                ];
                break;
            }
        }

        // Error monitoring (= ops maturity)
        foreach (self::MONITORING_PATTERNS as $name => $pattern) {
            if ($this->matchSources($allContent, $allSources, $pattern)) {
                $signals['error_monitoring'] = [
                    'value' => $name,
                    'confidence' => 0.9,
                    'evidence' => "Script pattern: {$name}",
                ];
                break;
            }
        }

        // Feature flags (= engineering maturity)
        foreach (self::FEATURE_FLAG_PATTERNS as $name => $pattern) {
            if ($this->matchSources($allContent, $allSources, $pattern)) {
                $signals['feature_flags'] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => "Script pattern: {$name}",
                ];
                break;
            }
        }

        // Headless CMS (= modern architecture)
        foreach (self::HEADLESS_CMS_PATTERNS as $name => $pattern) {
            if ($this->matchSources($allContent, $allSources, $pattern)) {
                $signals['headless_cms'] = [
                    'value' => $name,
                    'confidence' => 0.85,
                    'evidence' => "Script/asset pattern: {$name}",
                ];
                break;
            }
        }

        if ($signals === []) {
            return null;
        }

        $tags = array_map(fn($s) => $s['value'], $signals);

        return ['technology' => ['saas_signals' => $signals], '_tags' => $tags];
    }

    private function matchSources(string $allContent, array $sources, string $pattern): bool
    {
        if (preg_match($pattern, $allContent)) {
            return true;
        }

        foreach ($sources as $src) {
            if (preg_match($pattern, $src)) {
                return true;
            }
        }

        return false;
    }
}
