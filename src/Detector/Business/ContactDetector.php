<?php

namespace Scavier\Detector\Business;

use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\DiscoveryCollector;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class ContactDetector extends Detector
{
    private const CONTACT_KEYWORDS = ['contact', 'kontakt', 'about', 'o-nas', 'o-firmie', 'impressum', 'imprint', 'privacy', 'prywatno', 'regulamin', 'terms'];

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

        $results = [];

        // 1. Homepage: JSON-LD
        foreach ($html->jsonLd as $item) {
            $this->extractFromJsonLd($item, $results);
        }

        // 2. Homepage: mailto/tel links
        $this->extractLinksFromHtml($html, $results, 'Homepage');

        // 3. Homepage: meta author
        $authorEmail = $html->metaTag('author');
        if ($authorEmail !== null && filter_var($authorEmail, FILTER_VALIDATE_EMAIL) && !$this->hasEmail($results, $authorEmail)) {
            $results['emails'][] = [
                'value' => $authorEmail,
                'confidence' => 0.7,
                'evidence' => 'meta author tag',
            ];
        }

        // 4. Scan all discovered HTML pages matching contact keywords
        if ($discovery !== null) {
            foreach ($discovery->paths as $path => $response) {
                if (!$this->isContactPage($path)) {
                    continue;
                }

                $body = $discovery->body($path);
                if ($body !== null && str_contains($body, '<')) {
                    $this->extractFromRawHtml($body, $results, $path);
                }
            }
        }

        if (empty($results)) {
            return null;
        }

        return ['business' => ['contacts' => $results]];
    }

    private function extractLinksFromHtml(HtmlData $html, array &$results, string $source): void
    {
        foreach ($html->emails as $email) {
            if (!$this->hasEmail($results, $email)) {
                $results['emails'][] = [
                    'value' => $email,
                    'confidence' => 0.9,
                    'evidence' => "mailto: link ({$source})",
                ];
            }
        }

        foreach ($html->phones as $phone) {
            if (!$this->hasPhone($results, $phone)) {
                $results['phones'][] = [
                    'value' => $phone,
                    'confidence' => 0.9,
                    'evidence' => "tel: link ({$source})",
                ];
            }
        }
    }

    private function extractFromRawHtml(string $body, array &$results, string $path): void
    {
        // Extract mailto: links
        if (preg_match_all('/href=["\']mailto:([^"\'?]+)/i', $body, $matches)) {
            foreach ($matches[1] as $email) {
                $email = trim($email);
                if (filter_var($email, FILTER_VALIDATE_EMAIL) && !$this->hasEmail($results, $email)) {
                    $results['emails'][] = [
                        'value' => $email,
                        'confidence' => 0.9,
                        'evidence' => "mailto: link ({$path})",
                    ];
                }
            }
        }

        // Extract tel: links
        if (preg_match_all('/href=["\']tel:([^"\']+)/i', $body, $matches)) {
            foreach ($matches[1] as $phone) {
                $phone = trim($phone);
                if ($phone !== '' && !$this->hasPhone($results, $phone)) {
                    $results['phones'][] = [
                        'value' => $phone,
                        'confidence' => 0.9,
                        'evidence' => "tel: link ({$path})",
                    ];
                }
            }
        }

        // Extract JSON-LD from subpage
        if (preg_match_all('/<script[^>]*type=["\']application\/ld\+json["\'][^>]*>(.*?)<\/script>/si', $body, $matches)) {
            foreach ($matches[1] as $jsonStr) {
                $data = json_decode(trim($jsonStr), true);
                if (is_array($data)) {
                    $this->extractFromJsonLd($data, $results);
                }
            }
        }

        // Extract email patterns from visible text (lower confidence)
        $text = strip_tags($body);
        // Normalize whitespace to avoid concatenated words around emails
        $text = preg_replace('/\s+/', ' ', $text);
        if (preg_match_all('/(?<=\s|^)([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})(?=\s|$|[,;.)])/m', $text, $matches)) {
            foreach ($matches[0] as $email) {
                if (filter_var($email, FILTER_VALIDATE_EMAIL) && !$this->hasEmail($results, $email)) {
                    // Skip common false positives
                    if (preg_match('/@(example|test|localhost|sentry|wixpress|email|domain|yoursite|sample)\./i', $email)) {
                        continue;
                    }
                    $results['emails'][] = [
                        'value' => $email,
                        'confidence' => 0.6,
                        'evidence' => "Email in page text ({$path})",
                    ];
                }
            }
        }

        // Extract phone patterns from visible text — only with + prefix or clear phone context
        if (preg_match_all('/\+\d{1,3}[\s\-]?\d{2,4}[\s\-]?\d{3}[\s\-]?\d{2,4}[\s\-]?\d{0,4}/', $text, $matches)) {
            foreach ($matches[0] as $phone) {
                $phone = trim($phone);
                if (!$this->hasPhone($results, $phone)) {
                    $results['phones'][] = [
                        'value' => $phone,
                        'confidence' => 0.6,
                        'evidence' => "Phone in page text ({$path})",
                    ];
                }
            }
        }
    }

    private function extractFromJsonLd(array $item, array &$results): void
    {
        if (isset($item['email'])) {
            $email = str_replace('mailto:', '', $item['email']);
            if (!$this->hasEmail($results, $email)) {
                $results['emails'][] = [
                    'value' => $email,
                    'confidence' => 0.95,
                    'evidence' => 'JSON-LD email',
                ];
            }
        }

        if (isset($item['telephone'])) {
            if (!$this->hasPhone($results, $item['telephone'])) {
                $results['phones'][] = [
                    'value' => $item['telephone'],
                    'confidence' => 0.95,
                    'evidence' => 'JSON-LD telephone',
                ];
            }
        }

        $contactPoints = $item['contactPoint'] ?? [];
        if (isset($contactPoints['@type'])) {
            $contactPoints = [$contactPoints];
        }

        foreach ($contactPoints as $cp) {
            if (isset($cp['telephone']) && !$this->hasPhone($results, $cp['telephone'])) {
                $results['phones'][] = [
                    'value' => $cp['telephone'],
                    'confidence' => 0.95,
                    'evidence' => 'JSON-LD ContactPoint',
                ];
            }

            if (isset($cp['email'])) {
                $email = str_replace('mailto:', '', $cp['email']);
                if (!$this->hasEmail($results, $email)) {
                    $results['emails'][] = [
                        'value' => $email,
                        'confidence' => 0.95,
                        'evidence' => 'JSON-LD ContactPoint',
                    ];
                }
            }
        }

        $address = $item['address'] ?? null;
        if (is_array($address) && isset($address['@type']) && $address['@type'] === 'PostalAddress' && !isset($results['address'])) {
            $parts = array_filter([
                $address['streetAddress'] ?? null,
                $address['postalCode'] ?? null,
                $address['addressLocality'] ?? null,
                $address['addressCountry'] ?? null,
            ]);

            if (!empty($parts)) {
                $results['address'] = [
                    'value' => implode(', ', $parts),
                    'confidence' => 0.95,
                    'evidence' => 'JSON-LD PostalAddress',
                ];
            }
        }

        if (isset($item['@graph']) && is_array($item['@graph'])) {
            foreach ($item['@graph'] as $graphItem) {
                $this->extractFromJsonLd($graphItem, $results);
            }
        }
    }

    private function isContactPage(string $path): bool
    {
        $lower = strtolower($path);
        foreach (self::CONTACT_KEYWORDS as $keyword) {
            if (str_contains($lower, $keyword)) {
                return true;
            }
        }
        return false;
    }

    private function hasEmail(array $results, string $email): bool
    {
        foreach ($results['emails'] ?? [] as $e) {
            if (strcasecmp($e['value'], $email) === 0) {
                return true;
            }
        }
        return false;
    }

    private function hasPhone(array $results, string $phone): bool
    {
        foreach ($results['phones'] ?? [] as $p) {
            if ($p['value'] === $phone) {
                return true;
            }
        }
        return false;
    }
}
