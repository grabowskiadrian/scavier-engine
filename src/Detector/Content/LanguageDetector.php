<?php

namespace Scavier\Detector\Content;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class LanguageDetector extends Detector
{
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

        $language = null;
        $confidence = 0;
        $evidence = null;

        // html lang attribute (most reliable)
        if ($html->htmlLang !== null) {
            $language = $html->htmlLang;
            $confidence = 0.95;
            $evidence = 'html lang attribute';
        }

        // Content-Language header
        if ($language === null && $http !== null) {
            $contentLang = $http->header('content-language');
            if ($contentLang !== null) {
                $language = $contentLang;
                $confidence = 0.9;
                $evidence = 'Content-Language header';
            }
        }

        // meta http-equiv content-language
        if ($language === null) {
            $metaLang = $html->metaTag('content-language');
            if ($metaLang !== null) {
                $language = $metaLang;
                $confidence = 0.85;
                $evidence = 'meta content-language';
            }
        }

        // og:locale
        if ($language === null) {
            $ogLocale = $html->metaProperties['og:locale'] ?? null;
            if ($ogLocale !== null) {
                $language = $ogLocale;
                $confidence = 0.8;
                $evidence = 'og:locale';
            }
        }

        if ($language === null) {
            return null;
        }

        $result = [
            'value' => $language,
            'confidence' => $confidence,
            'evidence' => $evidence,
        ];

        // Extract hreflang alternatives
        $alternates = [];
        foreach ($html->links as $link) {
            if ($link['rel'] === 'alternate') {
                // Check if it has hreflang — we only have rel+href, but hreflang is in the tag
                // We can detect from the href pattern if it contains language codes
            }
        }

        // og:locale:alternate
        foreach ($html->metaProperties as $prop => $val) {
            if ($prop === 'og:locale:alternate') {
                $alternates[] = $val;
            }
        }

        if (!empty($alternates)) {
            $result['alternates'] = array_values(array_unique($alternates));
            $result['multilingual'] = true;
        }

        return ['content' => ['language' => $result]];
    }
}
