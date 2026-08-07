<?php

namespace Scavier\Collector\Data;

final class HtmlData
{
    /**
     * @param array<string, string> $meta name => content
     * @param array<string> $scripts Script src URLs
     * @param array<string> $inlineScripts Text content of <script> tags without src
     * @param array<string> $stylesheets Stylesheet href URLs
     * @param array<string, string> $metaProperties property => content (og:, twitter:, etc.)
     * @param array<array{rel: string, href: string}> $links All <link> tags
     * @param list<array> $jsonLd Parsed JSON-LD objects
     * @param array<string> $anchors All <a href> URLs from the page body
     * @param array<string> $emails Email addresses from mailto: links
     * @param array<string> $phones Phone numbers from tel: links
     */
    public function __construct(
        public readonly ?string $title,
        public readonly array $meta,
        public readonly array $scripts,
        public readonly array $inlineScripts,
        public readonly array $stylesheets,
        public readonly array $metaProperties,
        public readonly string $bodyText,
        public readonly ?string $htmlLang = null,
        public readonly array $links = [],
        public readonly array $jsonLd = [],
        public readonly array $anchors = [],
        public readonly array $emails = [],
        public readonly array $phones = [],
    ) {
    }

    public function metaTag(string $name): ?string
    {
        return $this->meta[strtolower($name)] ?? null;
    }

    public function hasScriptMatching(string $pattern): bool
    {
        foreach ($this->scripts as $src) {
            if (preg_match($pattern, $src)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string> Matching script URLs
     */
    public function scriptsMatching(string $pattern): array
    {
        return array_values(array_filter(
            $this->scripts,
            fn(string $src) => preg_match($pattern, $src)
        ));
    }

    /**
     * Check if any inline script content matches a pattern.
     */
    public function hasInlineScriptMatching(string $pattern): bool
    {
        foreach ($this->inlineScripts as $content) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }
}
