<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class EcommerceDetector extends Detector
{
    private const GENERATORS = [
        'Shopify' => '/shopify/i',
        'PrestaShop' => '/prestashop/i',
        'Magento' => '/magento/i',
        'OpenCart' => '/opencart/i',
    ];

    private const HTML_SIGNALS = [
        'Shopify' => ['/cdn\.shopify\.com/i', '/Shopify\.theme/i'],
        'WooCommerce' => ['/\/wp-content\/plugins\/woocommerce\//i', '/wc-cart-fragments/i'],
        'Magento' => ['/\/static\/version/i', '/mage\/cookies/i'],
        'PrestaShop' => ['/prestashop|modules\/ps_/i'],
        'BigCommerce' => ['/cdn\d*\.bigcommerce\.com/i', '/cdn\.bcapp/i'],
        'Squarespace Commerce' => ['/squarespace\.com.*commerce/i'],
    ];

    private const COOKIE_SIGNALS = [
        'WooCommerce' => '/^(woocommerce_|wp_woocommerce)/i',
        'Magento' => '/^mage-/i',
        'PrestaShop' => '/^PrestaShop-/i',
    ];

    private const PAYMENT_PATTERNS = [
        'Stripe' => ['/js\.stripe\.com/i', 0.95],
        'PayPal' => ['/paypal\.com\/sdk/i', 0.9],
        'Square' => ['/squareup\.com\/v2/i', 0.9],
        'Klarna' => ['/klarna\.com\/.*\.js/i', 0.85],
        'Afterpay' => ['/afterpay\.com|clearpay\.com/i', 0.85],
        'Braintree' => ['/braintreegateway\.com|braintree-api\.com/i', 0.9],
        'Adyen' => ['/checkoutshopper.*adyen/i', 0.9],
        'Mollie' => ['/js\.mollie\.com/i', 0.9],
        'Przelewy24' => ['/przelewy24\.pl/i', 0.85],
        'PayU' => ['/secure\.payu\./i', 0.85],
        'Tpay' => ['/js\.tpay\.com/i', 0.85],
        'Revolut Pay' => ['/revolut\.com\/embed/i', 0.85],
        'Apple Pay' => ['/apple-pay-sdk/i', 0.7],
        'Google Pay' => ['/pay\.google\.com\/gp/i', 0.7],
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

        $platform = null;
        $platformConfidence = 0;
        $platformEvidence = '';
        $payments = [];

        // Generator meta tag
        $generator = $html->metaTag('generator');
        if ($generator !== null) {
            foreach (self::GENERATORS as $name => $pattern) {
                if (preg_match($pattern, $generator)) {
                    $platform = $name;
                    $platformConfidence = 0.95;
                    $platformEvidence = "meta generator: {$generator}";
                    break;
                }
            }
        }

        // HTML signals
        if ($platform === null) {
            $body = $http?->body ?? '';
            foreach (self::HTML_SIGNALS as $name => $patterns) {
                foreach ($patterns as $pattern) {
                    if (preg_match($pattern, $body)) {
                        $platform = $name;
                        $platformConfidence = 0.7;
                        $platformEvidence = "HTML pattern: {$pattern}";
                        break 2;
                    }
                }
            }
        }

        // Cookie signals
        if ($platform === null && $http !== null) {
            foreach (self::COOKIE_SIGNALS as $name => $pattern) {
                foreach (array_keys($http->cookies) as $cookieName) {
                    if (preg_match($pattern, $cookieName)) {
                        $platform = $name;
                        $platformConfidence = 0.8;
                        $platformEvidence = "Cookie: {$cookieName}";
                        break 2;
                    }
                }
            }
        }

        // Payment providers (from script URLs)
        foreach (self::PAYMENT_PATTERNS as $name => [$pattern, $confidence]) {
            $matches = $html->scriptsMatching($pattern);
            if (!empty($matches)) {
                $payments[] = [
                    'value' => $name,
                    'confidence' => $confidence,
                    'evidence' => 'Script src: ' . $matches[0],
                ];
            }
        }

        if ($platform === null && empty($payments)) {
            return null;
        }

        $result = [];

        if ($platform !== null) {
            $result['platform'] = [
                'value' => $platform,
                'confidence' => $platformConfidence,
                'evidence' => $platformEvidence,
            ];
        }

        if (!empty($payments)) {
            $result['payments'] = $payments;
        }

        $tags = [];
        if ($platform !== null) {
            $tags[] = $platform;
        }
        foreach ($payments as $p) {
            $tags[] = $p['value'];
        }

        return ['technology' => ['ecommerce' => $result], '_tags' => $tags];
    }
}
