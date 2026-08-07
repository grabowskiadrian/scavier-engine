<?php

namespace Scavier\Detector\Business;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class CompanyDetector extends Detector
{
    private const BUSINESS_KEYWORDS = ['contact', 'kontakt', 'about', 'o-nas', 'o-firmie', 'impressum', 'imprint', 'privacy', 'prywatno', 'regulamin', 'terms', 'legal', 'prawne'];

    // Patterns for extracting business registration numbers
    private const REGISTRATION_PATTERNS = [
        'nip' => '/NIP[:\s]*(\d{3}[\-\s]?\d{3}[\-\s]?\d{2}[\-\s]?\d{2}|\d{10})/i',
        'regon' => '/REGON[:\s]*(\d{9,14})/i',
        'krs' => '/KRS[:\s]*(\d{10})/i',
        'vat' => '/(?:VAT|USt-IdNr|TVA|IVA)[:\s]*([A-Z]{2}\d{8,12})/i',
    ];

    public static function dependencies(): array
    {
        return [HtmlCollector::class, DiscoveryCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $html = $context->get(HtmlData::class);
        $discovery = $context->get(DiscoveryData::class);

        if ($html === null) {
            return null;
        }

        $result = [];

        // 1. Homepage: JSON-LD Organization
        foreach ($html->jsonLd as $item) {
            $this->extractFromJsonLd($item, $result);
        }

        // 2. og:site_name
        if (!isset($result['name'])) {
            $siteName = $html->metaProperties['og:site_name'] ?? null;
            if ($siteName !== null) {
                $result['name'] = [
                    'value' => $siteName,
                    'confidence' => 0.7,
                    'evidence' => 'og:site_name',
                ];
            }
        }

        // 3. application-name meta
        if (!isset($result['name'])) {
            $appName = $html->metaTag('application-name');
            if ($appName !== null) {
                $result['name'] = [
                    'value' => $appName,
                    'confidence' => 0.6,
                    'evidence' => 'meta application-name',
                ];
            }
        }

        // 4. Copyright year from homepage
        if (preg_match('/(?:©|\(c\)|copyright)\s*(\d{4})(?:\s*[-–]\s*(\d{4}))?/i', $html->bodyText, $cm)) {
            $result['copyright_year'] = (int) ($cm[2] ?? $cm[1]);
            if (isset($cm[2])) {
                $result['copyright_since'] = (int) $cm[1];
            }
        }

        // 5. Scan all discovered HTML pages matching business keywords
        if ($discovery !== null) {
            foreach ($discovery->paths as $path => $response) {
                $lower = strtolower($path);
                $isBusinessPage = false;

                foreach (self::BUSINESS_KEYWORDS as $keyword) {
                    if (str_contains($lower, $keyword)) {
                        $isBusinessPage = true;
                        break;
                    }
                }

                if (!$isBusinessPage) {
                    continue;
                }

                $body = $discovery->body($path);
                if ($body !== null && str_contains($body, '<')) {
                    $this->extractFromSubpage($body, $result, $path);
                }
            }
        }

        if (empty($result)) {
            return null;
        }

        return ['business' => ['company' => $result]];
    }

    private function extractFromSubpage(string $body, array &$result, string $path): void
    {
        // JSON-LD from subpage
        if (preg_match_all('/<script[^>]*type=["\']application\/ld\+json["\'][^>]*>(.*?)<\/script>/si', $body, $matches)) {
            foreach ($matches[1] as $jsonStr) {
                $data = json_decode(trim($jsonStr), true);
                if (is_array($data)) {
                    $this->extractFromJsonLd($data, $result);
                }
            }
        }

        // Registration numbers from page text
        $text = strip_tags($body);

        foreach (self::REGISTRATION_PATTERNS as $type => $pattern) {
            if (!isset($result[$type]) && preg_match($pattern, $text, $m)) {
                $result[$type] = [
                    'value' => trim($m[1]),
                    'confidence' => 0.85,
                    'evidence' => "Registration number on {$path}",
                ];
            }
        }

        // Copyright year from subpage if not found yet
        if (!isset($result['copyright_year']) && preg_match('/(?:©|\(c\)|copyright)\s*(\d{4})(?:\s*[-–]\s*(\d{4}))?/i', $text, $cm)) {
            $result['copyright_year'] = (int) ($cm[2] ?? $cm[1]);
            if (isset($cm[2])) {
                $result['copyright_since'] = (int) $cm[1];
            }
        }
    }

    private function extractFromJsonLd(array $item, array &$result): void
    {
        $type = $item['@type'] ?? null;

        if (in_array($type, ['Organization', 'Corporation', 'LocalBusiness', 'NGO', 'GovernmentOrganization', 'EducationalOrganization', 'MedicalOrganization', 'SportsOrganization'], true)) {
            if (isset($item['name']) && !isset($result['name'])) {
                $result['name'] = [
                    'value' => $item['name'],
                    'confidence' => 0.95,
                    'evidence' => "JSON-LD {$type}",
                ];
            }

            if (isset($item['url']) && !isset($result['url'])) {
                $result['url'] = $item['url'];
            }

            if (isset($item['logo'])) {
                $logo = is_array($item['logo']) ? ($item['logo']['url'] ?? null) : $item['logo'];
                if ($logo !== null && !isset($result['logo'])) {
                    $result['logo'] = $logo;
                }
            }

            if (isset($item['description']) && !isset($result['description'])) {
                $result['description'] = $item['description'];
            }

            if (isset($item['foundingDate']) && !isset($result['founding_date'])) {
                $result['founding_date'] = $item['foundingDate'];
            }

            if (isset($item['taxID']) && !isset($result['tax_id'])) {
                $result['tax_id'] = $item['taxID'];
            }

            if (isset($item['vatID']) && !isset($result['vat'])) {
                $result['vat'] = ['value' => $item['vatID'], 'confidence' => 0.95, 'evidence' => "JSON-LD {$type}"];
            }
        }

        if (isset($item['@graph']) && is_array($item['@graph'])) {
            foreach ($item['@graph'] as $graphItem) {
                $this->extractFromJsonLd($graphItem, $result);
            }
        }
    }
}
