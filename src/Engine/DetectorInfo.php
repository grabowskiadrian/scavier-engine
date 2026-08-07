<?php

namespace Scavier\Engine;

/**
 * Detector metadata: descriptions, required collectors, confidence model.
 *
 * Confidence scores (0.0 - 1.0):
 *   1.0  — Definitive: HTTP headers, DNS records, certificate fields (machine-readable, no ambiguity)
 *   0.95 — Meta tag: <meta name="generator"> (explicit declaration by site author)
 *   0.9  — Script URL match: external script src matched by regex (e.g. cdn.segment.com)
 *   0.85 — Inline script pattern: JS code pattern in inline <script> (e.g. fbq('init'...))
 *   0.8  — Cookie match: cookie name matched by pattern (e.g. hubspotutk)
 *   0.8  — WHOIS/ASN match: organization name matched by pattern
 *   0.75 — PTR record match: reverse DNS hostname pattern
 *   0.7  — HTML body pattern: regex on raw HTML body (e.g. /wp-content/)
 *   0.7  — IP range match: IP within known CIDR block
 *   0.6  — Text pattern: regex on visible page text (e.g. NIP, phone numbers)
 *   0.5  — Weak signal: unknown provider fallback, heuristic guess
 *
 * All scores are manually calibrated based on false-positive risk per evidence type.
 */
final class DetectorInfo
{
    private const DESCRIPTIONS = [
        // Technology
        'server' => 'Web server software and runtime (nginx, Apache, PHP version)',
        'cms' => 'Content management system with version, plugins, theme',
        'framework' => 'Frontend and backend frameworks (React, Vue, Laravel, Django)',
        'library' => 'JavaScript and CSS libraries with versions',
        'analytics' => 'Analytics tools and tracking IDs (GA4, GTM, Hotjar, FullStory)',
        'structureddata' => 'JSON-LD structured data types',
        'manifest' => 'PWA manifest detection',
        'ecommerce' => 'E-commerce platform and payment processors',
        'aireadiness' => 'AI integration signals (llms.txt, MCP, OpenAPI, crawler policy)',
        'font' => 'Font services (Google Fonts, Adobe Fonts)',
        'saassignal' => 'Strategic SaaS signals: auth, search, push, monitoring, feature flags, headless CMS',

        // Infrastructure
        'compression' => 'HTTP compression (gzip, brotli)',
        'cache' => 'Caching headers analysis',
        'performance' => 'Response timing, TTFB grading, page metrics',
        'dnsprovider' => 'DNS hosting provider',
        'cdn' => 'Content delivery network',
        'hosting' => 'Web hosting provider (via headers, IP, ASN)',
        'mailprovider' => 'Email service provider (via MX records)',
        'mailsender' => 'Email sending services from SPF (newsletters, transactional)',
        'registrar' => 'Domain registration, registrant, age, WHOIS data',
        'subdomain' => 'Subdomain discovery (TLS SAN, crt.sh, DNS brute)',
        'ipv6' => 'IPv4/IPv6 dual-stack support',

        // Security
        'securityheaders' => 'Security headers presence (HSTS, CSP, X-Frame-Options)',
        'cookie' => 'Cookie analysis and tracker identification',
        'emailsecurity' => 'Email security (SPF, DMARC)',
        'sslcertificate' => 'SSL certificate, TLS config, OCSP stapling',
        'securitytxt' => 'security.txt file detection',
        'exposure' => 'Sensitive file exposure (.env, .git, zone transfer)',
        'dnssecurity' => 'DNS security (DNSSEC, CAA, DANE)',

        // Business
        'social' => 'Social media profiles (8 platforms)',
        'contact' => 'Contact info from multi-page scan (email, phone, address)',
        'company' => 'Company data (name, NIP, REGON, KRS, VAT)',

        // Content
        'language' => 'Website language and multilingual support',
        'accessibility' => 'Accessibility features and overlay tools',
        'feed' => 'RSS/Atom feed detection',

        // Marketing
        'consent' => 'Cookie consent management tools',
        'chat' => 'Live chat and support widgets',
        'crm' => 'CRM and marketing automation platforms',
        'adnetwork' => 'Advertising networks',
        'abtesting' => 'A/B testing tools',
        'adstxt' => 'ads.txt file and ad exchanges',

        // SEO
        'robots' => 'robots.txt analysis and AI bot blocking',
        'sitemap' => 'sitemap.xml detection',
        'seo' => 'SEO audit (11 checks, meta tags, Open Graph)',
    ];

    private const REQUIRES = [
        // HTTP only (basic mode)
        'server' => ['HTTP'],
        'compression' => ['HTTP'],
        'cache' => ['HTTP'],
        'cookie' => ['HTTP'],

        // HTML parsing
        'cms' => ['HTTP', 'HTML'],
        'framework' => ['HTTP', 'HTML'],
        'library' => ['HTML'],
        'analytics' => ['HTML'],
        'structureddata' => ['HTML'],
        'ecommerce' => ['HTTP', 'HTML'],
        'font' => ['HTML'],
        'saassignal' => ['HTML'],
        'manifest' => ['Discovery'],
        'language' => ['HTML'],
        'accessibility' => ['HTML'],
        'feed' => ['HTML'],
        'consent' => ['HTML'],
        'chat' => ['HTML'],
        'crm' => ['HTTP', 'HTML'],
        'adnetwork' => ['HTML'],
        'abtesting' => ['HTML'],
        'social' => ['HTML'],
        'performance' => ['HTTP', 'HTML'],

        // DNS
        'dnsprovider' => ['DNS'],
        'mailprovider' => ['DNS'],
        'emailsecurity' => ['DNS'],
        'ipv6' => ['DNS'],
        'dnssecurity' => ['DNS'],

        // TLS
        'sslcertificate' => ['TLS'],

        // Discovery (multi-page)
        'securityheaders' => ['HTTP'],
        'robots' => ['Discovery'],
        'sitemap' => ['Discovery'],
        'seo' => ['HTML', 'Discovery'],
        'aireadiness' => ['Discovery'],
        'securitytxt' => ['Discovery'],
        'adstxt' => ['Discovery'],
        'contact' => ['HTML', 'Discovery'],
        'company' => ['HTML', 'Discovery'],
        'exposure' => ['Discovery', 'DNS'],

        // Heavy (WHOIS, crt.sh, etc.)
        'hosting' => ['HTTP', 'DNS', 'WHOIS'],
        'registrar' => ['RDAP', 'WHOIS'],
        'subdomain' => ['TLS', 'crt.sh', 'DNS brute'],
    ];

    public static function description(string $short): string
    {
        return self::DESCRIPTIONS[$short] ?? '';
    }

    public static function requires(string $short): array
    {
        return self::REQUIRES[$short] ?? [];
    }

    /**
     * @return array<string, string> short name => description
     */
    public static function all(): array
    {
        return self::DESCRIPTIONS;
    }

}
