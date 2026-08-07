<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\Data\HttpData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class HtmlCollector extends Collector
{
    public static function dependencies(): array
    {
        return [
            HttpCollector::class,
        ];
    }

    public function execute(Target $target, Context $context): void
    {
        $http = $context->get(HttpData::class);

        if ($http === null) {
            return;
        }

        $contentType = $http->header('content-type') ?? '';

        if (!str_contains($contentType, 'text/html') && !str_contains($contentType, 'application/xhtml')) {
            return;
        }

        libxml_use_internal_errors(true);
        $doc = new \DOMDocument();
        $doc->loadHTML($http->body, LIBXML_NOWARNING | LIBXML_NOERROR);
        libxml_clear_errors();

        $context->set(new HtmlData(
            title: $this->extractTitle($doc),
            meta: $this->extractMeta($doc),
            scripts: $this->extractScripts($doc),
            inlineScripts: $this->extractInlineScripts($doc),
            stylesheets: $this->extractStylesheets($doc),
            metaProperties: $this->extractMetaProperties($doc),
            bodyText: $this->extractBodyText($doc),
            htmlLang: $this->extractHtmlLang($doc),
            links: $this->extractLinks($doc),
            jsonLd: $this->extractJsonLd($doc),
            anchors: $this->extractAnchors($doc),
            emails: $this->extractMailtoLinks($doc),
            phones: $this->extractTelLinks($doc),
        ));
    }

    private function extractTitle(\DOMDocument $doc): ?string
    {
        $tags = $doc->getElementsByTagName('title');

        return $tags->length > 0 ? trim($tags->item(0)->textContent) : null;
    }

    /**
     * @return array<string, string>
     */
    private function extractMeta(\DOMDocument $doc): array
    {
        $meta = [];

        foreach ($doc->getElementsByTagName('meta') as $tag) {
            $name = $tag->getAttribute('name');
            $content = $tag->getAttribute('content');

            if ($name !== '' && $content !== '') {
                $meta[strtolower($name)] = $content;
            }
        }

        return $meta;
    }

    /**
     * @return array<string, string>
     */
    private function extractMetaProperties(\DOMDocument $doc): array
    {
        $props = [];

        foreach ($doc->getElementsByTagName('meta') as $tag) {
            $property = $tag->getAttribute('property');
            $content = $tag->getAttribute('content');

            if ($property !== '' && $content !== '') {
                $props[$property] = $content;
            }
        }

        return $props;
    }

    /**
     * @return array<string>
     */
    private function extractScripts(\DOMDocument $doc): array
    {
        $scripts = [];

        foreach ($doc->getElementsByTagName('script') as $tag) {
            $src = $tag->getAttribute('src');

            if ($src !== '') {
                $scripts[] = $src;
            }
        }

        return $scripts;
    }

    /**
     * @return array<string>
     */
    private function extractInlineScripts(\DOMDocument $doc): array
    {
        $scripts = [];

        foreach ($doc->getElementsByTagName('script') as $tag) {
            if ($tag->getAttribute('src') === '') {
                $content = trim($tag->textContent);

                if ($content !== '') {
                    $scripts[] = $content;
                }
            }
        }

        return $scripts;
    }

    /**
     * @return array<string>
     */
    private function extractStylesheets(\DOMDocument $doc): array
    {
        $sheets = [];

        foreach ($doc->getElementsByTagName('link') as $tag) {
            if (strtolower($tag->getAttribute('rel')) === 'stylesheet') {
                $href = $tag->getAttribute('href');

                if ($href !== '') {
                    $sheets[] = $href;
                }
            }
        }

        return $sheets;
    }

    /**
     * @return array<array{rel: string, href: string}>
     */
    private function extractLinks(\DOMDocument $doc): array
    {
        $links = [];

        foreach ($doc->getElementsByTagName('link') as $tag) {
            $rel = $tag->getAttribute('rel');
            $href = $tag->getAttribute('href');

            if ($rel !== '' && $href !== '') {
                $links[] = ['rel' => strtolower($rel), 'href' => $href];
            }
        }

        return $links;
    }

    private function extractBodyText(\DOMDocument $doc): string
    {
        $body = $doc->getElementsByTagName('body');

        if ($body->length === 0) {
            return '';
        }

        return trim($body->item(0)->textContent);
    }

    private function extractHtmlLang(\DOMDocument $doc): ?string
    {
        $html = $doc->getElementsByTagName('html');

        if ($html->length === 0) {
            return null;
        }

        $lang = $html->item(0)->getAttribute('lang');

        return $lang !== '' ? $lang : null;
    }

    /**
     * @return list<array>
     */
    private function extractJsonLd(\DOMDocument $doc): array
    {
        $results = [];

        foreach ($doc->getElementsByTagName('script') as $tag) {
            if (strtolower($tag->getAttribute('type')) === 'application/ld+json') {
                $data = json_decode(trim($tag->textContent), true);

                if (is_array($data)) {
                    $results[] = $data;
                }
            }
        }

        return $results;
    }

    /**
     * @return array<string>
     */
    private function extractAnchors(\DOMDocument $doc): array
    {
        $urls = [];

        foreach ($doc->getElementsByTagName('a') as $tag) {
            $href = $tag->getAttribute('href');

            if ($href !== '' && str_starts_with($href, 'http')) {
                $urls[] = $href;
            }
        }

        return $urls;
    }

    /**
     * @return array<string>
     */
    private function extractMailtoLinks(\DOMDocument $doc): array
    {
        $emails = [];

        foreach ($doc->getElementsByTagName('a') as $tag) {
            $href = $tag->getAttribute('href');

            if (str_starts_with(strtolower($href), 'mailto:')) {
                $email = trim(str_replace('mailto:', '', explode('?', $href)[0]));

                if ($email !== '' && !in_array($email, $emails, true)) {
                    $emails[] = $email;
                }
            }
        }

        return $emails;
    }

    /**
     * @return array<string>
     */
    private function extractTelLinks(\DOMDocument $doc): array
    {
        $phones = [];

        foreach ($doc->getElementsByTagName('a') as $tag) {
            $href = $tag->getAttribute('href');

            if (str_starts_with(strtolower($href), 'tel:')) {
                $phone = trim(str_replace('tel:', '', $href));

                if ($phone !== '' && !in_array($phone, $phones, true)) {
                    $phones[] = $phone;
                }
            }
        }

        return $phones;
    }
}
