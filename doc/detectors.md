# Detectors

Detectors analyze data collected by Collectors and extract structured knowledge. Each detector returns a `?array` — `null` means "nothing detected".

All detectors live in `src/Detector/` (organized by category) and are auto-discovered. Each detector extends `Scavier\Engine\Contract\Detector` and implements:

- `dependencies(): array` — lists collectors or other detectors that must run first
- `detect(Context $context): ?array` — returns structured output or `null`

Every detected fact follows a standard format:

```json
{
  "value": "Cloudflare",
  "confidence": 0.9,
  "evidence": "HTTP header: cf-ray"
}
```

## Confidence scale

| Score | Evidence type | Example |
|-------|--------------|---------|
| **1.0** | Definitive: HTTP header, DNS record, certificate field | `Server: nginx` |
| **0.95** | Meta tag: `<meta name="generator">` | `WordPress 6.4` |
| **0.9** | External script URL match | `cdn.segment.com/analytics.js` |
| **0.85** | Inline script pattern | `fbq('init', ...)` |
| **0.8** | Cookie name or WHOIS/ASN match | `hubspotutk` cookie |
| **0.75** | PTR record match | `server.hetzner.com` |
| **0.7** | HTML body pattern or IP range | `/wp-content/` in HTML |
| **0.6** | Text pattern | Phone number, NIP regex |
| **0.5** | Weak/heuristic signal | Unknown provider fallback |

## Detector-to-detector dependencies

Some detectors depend on other detectors (not just collectors):

- `SeoDetector` depends on `RobotsDetector` + `SitemapDetector`
- `AiReadinessDetector` depends on `RobotsDetector`

---

## Technology

### ServerDetector

Identifies web server software and runtime from HTTP headers.

**Short name:** `server`
**Dependencies:** `HttpCollector`
**Output key:** `technology.web_server`, `technology.runtime`

Detects: Apache, nginx, LiteSpeed, IIS, Caddy, openresty, Tengine, Cloudflare. Reads `X-Powered-By` for runtime (PHP, ASP.NET, etc.). Extracts version when available.

### CmsDetector

Identifies the CMS or site builder platform.

**Short name:** `cms`
**Dependencies:** `HttpCollector`, `HtmlCollector`
**Output key:** `technology.cms`

Detects: WordPress, Joomla, Drupal, TYPO3, Hugo, Jekyll, Ghost, Wix, Squarespace, Webflow.

Detection signals (in priority order):
1. `<meta name="generator">` tag (0.95)
2. HTTP headers like `x-drupal-cache` (0.9)
3. Cookie names like `wordpress_logged_in` (0.8)
4. HTML body patterns like `/wp-content/` (0.7)

For WordPress, also extracts: plugin slugs, theme name, version.

### FrameworkDetector

Detects frontend and backend frameworks.

**Short name:** `framework`
**Dependencies:** `HttpCollector`, `HtmlCollector`
**Output key:** `technology.frameworks`

| Type | Detected |
|------|----------|
| Frontend (scripts) | React, Vue.js, Angular, Svelte, Alpine.js |
| Frontend (markers) | Next.js, Nuxt.js, Gatsby, Svelte, Livewire |
| Backend (cookies) | Laravel, Rails, Django, ASP.NET, CakePHP, CodeIgniter |
| Backend (headers) | ASP.NET |

Each result includes `type: "frontend"` or `type: "backend"`.

### LibraryDetector

Detects JS/CSS libraries with version extraction.

**Short name:** `library`
**Dependencies:** `HtmlCollector`
**Output key:** `technology.libraries`

Detects 24 libraries: jQuery, Bootstrap, Font Awesome, Lodash, Moment.js, Axios, HTMX, Turbo, Livewire, Tailwind CSS, Swiper, GSAP, D3.js, Chart.js, Three.js, Leaflet, Mapbox, Socket.io, Lottie, AOS, Anime.js, Highlight.js, Prism.js, Slick, Owl Carousel.

Extracts version from URL path patterns (e.g. `/@3.7.1/`).

### AnalyticsDetector

Detects analytics, tag management, and session recording tools. Extracts tracking IDs.

**Short name:** `analytics`
**Dependencies:** `HtmlCollector`
**Output key:** `marketing.analytics`

Detects 21 tools: GA4, Universal Analytics, Google Tag Manager, Facebook Pixel, Matomo, Plausible, Fathom, Mixpanel, Segment, Amplitude, Heap, PostHog, Tealium, Adobe Launch, Hotjar, Clarity, FullStory, LogRocket, Mouseflow, Smartlook, Lucky Orange.

Extracted tracking IDs:

| Key | Format |
|-----|--------|
| `ga4` | `G-XXXXXXX` |
| `universal_analytics` | `UA-XXXXX-X` |
| `gtm` | `GTM-XXXXXX` |
| `google_tag` | `GT-XXXXXX` |
| `facebook_pixel` | numeric |

### EcommerceDetector

Identifies e-commerce platforms and payment providers.

**Short name:** `ecommerce`
**Dependencies:** `HttpCollector`, `HtmlCollector`
**Output key:** `technology.ecommerce`

**Platforms:** Shopify, WooCommerce, Magento, PrestaShop, BigCommerce, OpenCart, Squarespace Commerce.

**Payment providers (14):** Stripe, PayPal, Square, Braintree, Adyen, Mollie, Klarna, Afterpay, Przelewy24, PayU, Tpay, Revolut Pay, Apple Pay, Google Pay.

### FontDetector

Detects external web font services.

**Short name:** `font`
**Dependencies:** `HtmlCollector`
**Output key:** `technology.fonts`

Detects: Google Fonts, Adobe Fonts, Bunny Fonts. Extracts font family names from Google Fonts URL parameters.

### StructuredDataDetector

Enumerates JSON-LD `@type` values on the homepage.

**Short name:** `structureddata`
**Dependencies:** `HtmlCollector`
**Output key:** `technology.structured_data`

Returns: `format`, `types[]`, `count`.

### ManifestDetector

Detects Progressive Web App (PWA) configuration.

**Short name:** `manifest`
**Dependencies:** `DiscoveryCollector`
**Output key:** `technology.pwa`

Checks `/manifest.json` and `/manifest.webmanifest`. Extracts `name`, `display`, `start_url`, `theme_color`.

### AiReadinessDetector

Assesses how AI-agent-friendly the site is.

**Short name:** `aireadiness`
**Dependencies:** `DiscoveryCollector`, `RobotsDetector`
**Output key:** `technology.ai_readiness`

| Signal | Source |
|--------|--------|
| `llms_txt` | `/llms.txt` presence, title, size |
| `mcp_server` | `/.well-known/mcp.json` presence, endpoint |
| `api_docs` | `/openapi.json` or `/swagger.json`, title, version |
| `ai_crawler_policy` | robots.txt AI bot analysis |

Tracked AI bots: GPTBot, ChatGPT-User, Google-Extended, CCBot, anthropic-ai, ClaudeBot, Claude-Web, Bytespider, Diffbot, FacebookBot, PerplexityBot, Cohere-ai.

### SaasSignalDetector

Detects strategic SaaS signals that reveal business architecture maturity.

**Short name:** `saassignal`
**Dependencies:** `HtmlCollector`
**Output key:** `technology.saas_signals`

| Signal | Detected services |
|--------|-------------------|
| Auth providers | Auth0, Okta, Firebase Auth, Clerk, Supabase Auth |
| Search engines | Algolia, Doofinder, Meilisearch, Elasticsearch, Typesense |
| Push notifications | OneSignal, PushEngage, WebPushr, Pushwoosh |
| Error monitoring | Sentry, Datadog, New Relic, Bugsnag, Rollbar |
| Feature flags | LaunchDarkly, Unleash, Flagsmith, Statsig |
| Headless CMS | Contentful, Strapi, Sanity, Prismic, Storyblok |

One provider per signal category (first match wins).

---

## Infrastructure

### CdnDetector

Identifies the Content Delivery Network.

**Short name:** `cdn`
**Dependencies:** `HttpCollector`, `DnsCollector`
**Output key:** `infrastructure.cdn`

Detects: Cloudflare, Fastly, AWS CloudFront, Akamai, Sucuri, KeyCDN, Bunny CDN, Netlify, Vercel, Azure CDN, Google Cloud CDN.

Uses multiple signals: CDN-specific headers, `Server` header, DNS CNAME targets. Multiple signals for the same provider boost confidence.

### HostingDetector

Identifies the web hosting/cloud provider.

**Short name:** `hosting`
**Dependencies:** `HttpCollector`, `DnsCollector`, `WhoisCollector`
**Output key:** `infrastructure.hosting`

Multi-signal detection (30+ providers):

| Signal type | Confidence | Examples |
|-------------|-----------|----------|
| Hosting-specific headers | 0.95 | Kinsta, WP Engine, Pantheon |
| `Server` header | 0.9 | Netlify, Vercel, GitHub Pages |
| DNS CNAME targets | 0.85 | AWS, Google Cloud, Azure, Fly.io |
| WHOIS ASN/org | 0.8 | Hetzner, OVH, DigitalOcean |
| PTR records | 0.75 | Reverse DNS patterns |
| IP CIDR ranges | 0.7 | Cloudflare, Hetzner |

### DnsProviderDetector

Identifies the DNS hosting provider from NS records.

**Short name:** `dnsprovider`
**Dependencies:** `DnsCollector`
**Output key:** `infrastructure.dns`

Detects 16 providers: Cloudflare, AWS Route 53, Google Cloud DNS, Google Domains, Azure DNS, DigitalOcean, Hetzner, OVH, GoDaddy, Namecheap, NS1, DNSimple, ClouDNS, Linode/Akamai, Vercel, Netlify.

### MailProviderDetector

Identifies who hosts the domain's mailboxes (MX-based).

**Short name:** `mailprovider`
**Dependencies:** `DnsCollector`
**Output key:** `infrastructure.mail`

Detects 12 providers: Google Workspace, Microsoft 365, Zoho Mail, ProtonMail, OVH, Yandex Mail, MXRoute, Fastmail, Amazon SES, Mailgun, SendGrid, Postmark.

### MailSenderDetector

Detects email sending services from SPF records. Distinct from MailProviderDetector (mailbox hosting vs. email sending).

**Short name:** `mailsender`
**Dependencies:** `DnsCollector`
**Output key:** `infrastructure.mail_senders`

Detects 19 services: MailerLite, Mailchimp, SendGrid, GetResponse, ActiveCampaign, Brevo, Klaviyo, ConvertKit, Omnisend, Campaign Monitor, Constant Contact, HubSpot, Amazon SES, Postmark, Mailgun, SparkPost, Google Workspace, Microsoft 365, Zoho.

### RegistrarDetector

Reports domain registration information.

**Short name:** `registrar`
**Dependencies:** `RdapCollector`, `DomainWhoisCollector`
**Output key:** `domain.registration`

Prefers RDAP data, falls back to WHOIS for each field. Calculates domain age and categorizes as `new` (<1yr), `established` (<5yr), or `mature`. Flags domains expiring within 30 days.

Fields: `domain`, `registrar`, `registered`, `domain_age_years`, `domain_age_category`, `expires`, `expiring_soon`, `updated`, `status[]`, `registrant`, `registrant_organization`, `registrant_country`, `registrant_email`, `dnssec`.

### SubdomainDetector

Enumerates subdomains and classifies them by service type.

**Short name:** `subdomain`
**Dependencies:** `TlsCollector`, `CrtshCollector`, `SubdomainDnsCollector`
**Output key:** `infrastructure.subdomains`

Three sources: TLS SAN entries (1.0), Certificate Transparency via crt.sh (0.95), DNS brute force (1.0). Classifies each subdomain into service types: mail, app, api, cdn, dev, docs, admin, shop, blog, auth, monitoring, ci, database, vpn.

### PerformanceDetector

Reports HTTP performance metrics.

**Short name:** `performance`
**Dependencies:** `HtmlCollector`
**Output key:** `infrastructure.performance`

Fields: `total_time`, `dns_lookup`, `tcp_connect`, `ttfb`, `ttfb_grade`, `page_weight_bytes`, `script_count`, `stylesheet_count`, `inline_script_count`, `http_version`.

TTFB grading per Google Web Vitals: good (<=0.8s), needs_improvement (<=1.8s), poor (>1.8s).

### Ipv6Detector

Determines IPv4/IPv6 support.

**Short name:** `ipv6`
**Dependencies:** `DnsCollector`
**Output key:** `infrastructure.ip`

Reports `stack` as `dual-stack`, `ipv6-only`, or `ipv4-only`.

### CompressionDetector

Checks HTTP response compression.

**Short name:** `compression`
**Dependencies:** `HttpCollector`
**Output key:** `infrastructure.compression`

Reports `enabled` (bool) and `algorithm` (e.g. `gzip`, `br`).

### CacheDetector

Reports HTTP caching configuration.

**Short name:** `cache`
**Dependencies:** `HttpCollector`
**Output key:** `infrastructure.cache`

Reads: `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, `Age`, plus CDN cache indicators (`x-cache`, `cf-cache-status`, `x-varnish`, `x-served-by`).

---

## Security

### SecurityHeadersDetector

Audits HTTP security headers and computes a grade.

**Short name:** `securityheaders`
**Dependencies:** `HttpCollector`
**Output key:** `security.headers`, `audit.security_score`

Checks 10 headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, COOP, COEP, CORP.

Grades: A (>=90%), B (>=70%), C (>=50%), D (>=30%), F (<30%).

HSTS analysis: checks `max-age`, `includeSubDomains`, `preload`. Warns if max-age < 1 year.
CSP analysis: flags `unsafe-inline`, `unsafe-eval`, wildcard sources.

### SslCertificateDetector

Reports SSL/TLS certificate and connection security.

**Short name:** `sslcertificate`
**Dependencies:** `TlsCollector`
**Output key:** `domain.ssl`, `security.tls`, `audit.ssl_issues` (if issues found)

Matches issuer against 10 known CAs: Let's Encrypt, DigiCert, Sectigo, GlobalSign, GoDaddy, Amazon, Google Trust Services, Cloudflare, ZeroSSL, Buypass.

Issues flagged:
- Expired certificate (critical)
- Expiring within 30 days (warning)
- Legacy TLS protocol (TLSv1, TLSv1.1)

### CookieDetector

Enumerates cookies and identifies known trackers.

**Short name:** `cookie`
**Dependencies:** `HttpCollector`
**Output key:** `security.cookies`

Known trackers: Google Analytics (`_ga`, `_gid`, `_gat`), Facebook Pixel (`_fbp`, `_fbc`), Google Ads (`_gcl_au`, `_gcl_aw`), Microsoft Ads, Hotjar, HubSpot.

Also checks per-cookie security attributes: `secure`, `httponly`, `samesite`.

### EmailSecurityDetector

Checks email authentication records.

**Short name:** `emailsecurity`
**Dependencies:** `DnsCollector`
**Output key:** `security.email`

Checks SPF (`v=spf1`) and DMARC (`v=dmarc1`) records. Extracts DMARC policy (`none`, `quarantine`, `reject`).

### DnsSecurityDetector

Checks DNS-level security configurations.

**Short name:** `dnssecurity`
**Dependencies:** `DnsCollector`
**Output key:** `domain.dns_security`

Checks: DNSSEC (DNSKEY presence), CAA records (permitted issuers), DANE/TLSA records.

### ExposureDetector

Detects critical security exposures.

**Short name:** `exposure`
**Dependencies:** `DiscoveryCollector`, `DnsZoneTransferCollector`
**Output key:** `audit.exposures`

| Exposure | Risk | Validation |
|----------|------|------------|
| `/.env` accessible | Critical | Checks for `KEY=VALUE` patterns without HTML |
| `/.git/HEAD` accessible | Critical | Checks for `ref:` or 40-char hex hash |
| DNS zone transfer (AXFR) | Critical | Reports vulnerable nameservers and record count |

Returns `null` if no exposures found.

### SecurityTxtDetector

Checks for `security.txt` vulnerability disclosure file.

**Short name:** `securitytxt`
**Dependencies:** `DiscoveryCollector`
**Output key:** `security.security_txt`

Parses: Contact, Expires, Encryption, Acknowledgments, Preferred-Languages, Canonical, Policy, Hiring.

---

## Business

### CompanyDetector

Extracts company identity information.

**Short name:** `company`
**Dependencies:** `HtmlCollector`, `DiscoveryCollector`
**Output key:** `business.company`

Sources (in priority order):
1. JSON-LD Organization/Corporation/LocalBusiness (0.95)
2. `og:site_name` (0.7)
3. `<meta application-name>` (0.6)

Also scans subpages (contact, about, impressum) for registration numbers: NIP, REGON, KRS, VAT (PL/EU).

Fields: `name`, `url`, `logo`, `description`, `founding_date`, `tax_id`, `vat`, `copyright_year`, `copyright_since`, `nip`, `regon`, `krs`.

### ContactDetector

Extracts contact information via multi-page scan.

**Short name:** `contact`
**Dependencies:** `HtmlCollector`, `DiscoveryCollector`
**Output key:** `business.contacts`

Sources:
1. JSON-LD `email`, `telephone`, `contactPoint`, `PostalAddress` (0.95)
2. `mailto:` and `tel:` links from homepage (0.9)
3. Subpages matching contact keywords (0.6-0.9)

Deduplicates and filters false positives (example.com, test, localhost).

### SocialDetector

Detects official social media profiles.

**Short name:** `social`
**Dependencies:** `HtmlCollector`
**Output key:** `business.social`

Detects 8 platforms: Facebook, Twitter/X, LinkedIn, Instagram, YouTube, TikTok, GitHub, Pinterest.

Sources: JSON-LD `sameAs` (0.95), anchor hrefs (0.8), OG meta properties (0.7).

---

## Content

### LanguageDetector

Determines primary language and multilingual support.

**Short name:** `language`
**Dependencies:** `HtmlCollector`
**Output key:** `content.language`

Priority: `<html lang>` (0.95) > `Content-Language` header (0.9) > `<meta http-equiv="content-language">` (0.85) > `og:locale` (0.8).

Detects `og:locale:alternate` for multilingual sites.

### AccessibilityDetector

Checks basic accessibility signals and overlay tools.

**Short name:** `accessibility`
**Dependencies:** `HtmlCollector`
**Output key:** `content.accessibility`

Checks: `lang` attribute, `viewport` meta, overlay tools (AccessiBe, UserWay, AudioEye, EqualWeb, MaxAccess). Computes pass/total score.

### FeedDetector

Detects RSS/Atom feeds.

**Short name:** `feed`
**Dependencies:** `HtmlCollector`
**Output key:** `content.feeds`

Scans `<link rel="alternate">` tags. Identifies type by URL extension or path pattern.

---

## Marketing

### CrmDetector

Detects CRM and marketing automation platforms.

**Short name:** `crm`
**Dependencies:** `HttpCollector`, `HtmlCollector`
**Output key:** `marketing.crm`

Detects 16 platforms: HubSpot, Salesforce Pardot, Marketo, ActiveCampaign, Pipedrive, Freshsales, Zoho CRM, Keap (Infusionsoft), Drip, Klaviyo, Mailchimp, Brevo, GetResponse, MailerLite, ConvertKit, Omnisend.

Detection: script URLs (0.9), inline patterns (0.85), cookies (0.9).

### AdNetworkDetector

Detects advertising networks.

**Short name:** `adnetwork`
**Dependencies:** `HtmlCollector`
**Output key:** `marketing.advertising`

Detects 13 networks: Google AdSense, Google Ad Manager, Google Ads, Amazon Publisher Services, Media.net, Ezoic, Mediavine, AdThrive (Raptive), Taboola, Outbrain, Carbon Ads, BuySellAds, PropellerAds.

### AdsTxtDetector

Parses `/ads.txt` to identify programmatic ad exchanges.

**Short name:** `adstxt`
**Dependencies:** `DiscoveryCollector`
**Output key:** `marketing.ads_txt`

Maps 15 known exchanges: Google, AppNexus/Xandr, OpenX, Rubicon/Magnite, PubMatic, Index Exchange, Smart AdServer, Amazon, PulsePoint, Sovrn, TripleLift, Criteo, Media.net, Taboola, Outbrain.

### AbTestingDetector

Detects A/B testing and experimentation platforms.

**Short name:** `abtesting`
**Dependencies:** `HtmlCollector`
**Output key:** `marketing.ab_testing`

Detects 9 platforms: Optimizely, VWO, Google Optimize, LaunchDarkly, Split.io, Statsig, AB Tasty, Convert, Kameleoon.

### ChatDetector

Detects live chat and customer messaging platforms.

**Short name:** `chat`
**Dependencies:** `HtmlCollector`
**Output key:** `marketing.chat`

Detects 11 platforms: Intercom, Drift, Zendesk, Crisp, Tawk.to, LiveChat, HubSpot Chat, Tidio, Freshchat, Olark, Chatwoot.

### ConsentDetector

Detects cookie consent management platforms.

**Short name:** `consent`
**Dependencies:** `HtmlCollector`
**Output key:** `marketing.consent`

Detects 10 CMPs: Cookiebot, OneTrust, CookieYes, Quantcast, Osano, Termly, iubenda, Cookie Notice, Complianz, CookieScript.

---

## SEO

### RobotsDetector

Parses robots.txt and analyzes crawler access rules.

**Short name:** `robots`
**Dependencies:** `DiscoveryCollector`
**Output key:** `seo.robots`

Parses directives: User-agent, Disallow, Allow, Crawl-delay, Sitemap. Detects `Disallow: /` for all crawlers. Tracks 12 specific AI bots being blocked.

### SitemapDetector

Checks for sitemap.xml.

**Short name:** `sitemap`
**Dependencies:** `DiscoveryCollector`
**Output key:** `seo.sitemap`

Detects sitemap index vs. regular sitemap. Counts sub-sitemaps or URL entries.

### SeoDetector

Aggregates an SEO health overview.

**Short name:** `seo`
**Dependencies:** `HtmlCollector`, `RobotsDetector`, `SitemapDetector`
**Output key:** `seo.overview`, `audit.seo_score`

Checks 9 signals: title (presence + length), meta description (presence + length), canonical link, Open Graph tags, Twitter Card tags, viewport meta, lang attribute, JSON-LD structured data, meta robots (noindex/nofollow). Also reads robots.txt and sitemap existence from dependent detectors.
