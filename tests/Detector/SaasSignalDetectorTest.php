<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Detector\Technology\SaasSignalDetector;
use Scavier\Engine\Context;

final class SaasSignalDetectorTest extends TestCase
{
    private function contextWithScripts(array $scripts = [], array $inline = []): Context
    {
        $context = new Context();
        $context->set(new HtmlData(
            title: 'Test', meta: [], scripts: $scripts, inlineScripts: $inline,
            stylesheets: [], metaProperties: [], bodyText: '',
        ));
        return $context;
    }

    public function testDetectsAuth0(): void
    {
        $result = (new SaasSignalDetector())->detect(
            $this->contextWithScripts(['https://cdn.auth0.com/js/auth0-spa-js/2.0/auth0-spa-js.production.js'])
        );

        $this->assertSame('Auth0', $result['technology']['saas_signals']['auth']['value']);
    }

    public function testDetectsAlgolia(): void
    {
        $result = (new SaasSignalDetector())->detect(
            $this->contextWithScripts(['https://cdn.jsdelivr.net/npm/algoliasearch@4.14.3'])
        );

        $this->assertSame('Algolia', $result['technology']['saas_signals']['search']['value']);
    }

    public function testDetectsOneSignal(): void
    {
        $result = (new SaasSignalDetector())->detect(
            $this->contextWithScripts(['https://cdn.onesignal.com/sdks/OneSignalSDK.js'])
        );

        $this->assertSame('OneSignal', $result['technology']['saas_signals']['push_notifications']['value']);
    }

    public function testDetectsFirebaseFromInline(): void
    {
        $result = (new SaasSignalDetector())->detect(
            $this->contextWithScripts([], ['firebase.initializeApp(config); firebaseauth.signIn();'])
        );

        $this->assertSame('Firebase Auth', $result['technology']['saas_signals']['auth']['value']);
    }

    public function testReturnsNullWhenNoSignals(): void
    {
        $this->assertNull((new SaasSignalDetector())->detect(
            $this->contextWithScripts(['https://example.com/app.js'])
        ));
    }

    public function testDetectsSentry(): void
    {
        $result = (new SaasSignalDetector())->detect(
            $this->contextWithScripts(['https://browser.sentry-cdn.com/7.0.0/bundle.min.js'])
        );

        $this->assertSame('Sentry', $result['technology']['saas_signals']['error_monitoring']['value']);
    }

    public function testDetectsLaunchDarkly(): void
    {
        $result = (new SaasSignalDetector())->detect(
            $this->contextWithScripts(['https://app.launchdarkly.com/sdk/ld-cdn.js'])
        );

        $this->assertSame('LaunchDarkly', $result['technology']['saas_signals']['feature_flags']['value']);
    }

    public function testDetectsContentful(): void
    {
        $result = (new SaasSignalDetector())->detect(
            $this->contextWithScripts(['https://images.ctfassets.net/abc123/image.jpg'])
        );

        $this->assertSame('Contentful', $result['technology']['saas_signals']['headless_cms']['value']);
    }

    public function testMultipleSignals(): void
    {
        $result = (new SaasSignalDetector())->detect(
            $this->contextWithScripts([
                'https://cdn.auth0.com/js/auth0.js',
                'https://cdn.jsdelivr.net/npm/algoliasearch@4',
                'https://cdn.onesignal.com/sdks/OneSignalSDK.js',
                'https://browser.sentry-cdn.com/7.0.0/bundle.min.js',
            ])
        );

        $this->assertArrayHasKey('auth', $result['technology']['saas_signals']);
        $this->assertArrayHasKey('search', $result['technology']['saas_signals']);
        $this->assertArrayHasKey('push_notifications', $result['technology']['saas_signals']);
        $this->assertArrayHasKey('error_monitoring', $result['technology']['saas_signals']);
    }
}
