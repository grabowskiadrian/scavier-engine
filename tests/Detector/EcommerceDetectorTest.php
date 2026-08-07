<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Technology\EcommerceDetector;
use Scavier\Engine\Context;

final class EcommerceDetectorTest extends TestCase
{
    private function context(array $meta = [], string $body = '', array $scripts = [], array $cookies = []): Context
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: $body, cookies: $cookies));
        $context->set(new HtmlData(
            title: null, meta: $meta, scripts: $scripts, inlineScripts: [],
            stylesheets: [], metaProperties: [], bodyText: '',
        ));
        return $context;
    }

    public function testDetectsShopifyViaGenerator(): void
    {
        $result = (new EcommerceDetector())->detect($this->context(['generator' => 'Shopify']));
        $this->assertSame('Shopify', $result['technology']['ecommerce']['platform']['value']);
    }

    public function testDetectsWooCommerceViaHtml(): void
    {
        $result = (new EcommerceDetector())->detect($this->context(body: '<script src="/wp-content/plugins/woocommerce/assets/js/frontend.js"></script>'));
        $this->assertSame('WooCommerce', $result['technology']['ecommerce']['platform']['value']);
    }

    public function testDetectsStripePayment(): void
    {
        $result = (new EcommerceDetector())->detect($this->context(scripts: ['https://js.stripe.com/v3/']));
        $this->assertSame('Stripe', $result['technology']['ecommerce']['payments'][0]['value']);
    }

    public function testDetectsPlatformAndPayments(): void
    {
        $result = (new EcommerceDetector())->detect($this->context(
            body: '<script src="/wp-content/plugins/woocommerce/assets/js/main.js"></script>',
            scripts: ['https://js.stripe.com/v3/', 'https://www.paypal.com/sdk/js?client-id=abc'],
        ));
        $this->assertSame('WooCommerce', $result['technology']['ecommerce']['platform']['value']);
        $paymentNames = array_column($result['technology']['ecommerce']['payments'], 'value');
        $this->assertContains('Stripe', $paymentNames);
        $this->assertContains('PayPal', $paymentNames);
    }

    public function testReturnsNullWhenNoEcommerce(): void
    {
        $this->assertNull((new EcommerceDetector())->detect($this->context()));
    }
}
