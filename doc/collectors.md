# Collectors

Collectors fetch raw data from external sources (HTTP, DNS, WHOIS, etc.) and store typed data objects in the shared `Context`. Detectors then read from Context to extract knowledge.

All collectors live in `src/Collector/` and are auto-discovered by the engine. Each collector extends `Scavier\Engine\Contract\Collector` and implements two methods:

- `dependencies(): array` — lists other collectors that must run first
- `execute(Target $target, Context $context): void` — fetches data and stores it via `$context->set()`

## Dependency graph

```
HttpCollector          (no deps)
  +-- HtmlCollector
  +-- DiscoveryCollector

DnsCollector           (no deps)
  +-- WhoisCollector
  +-- DnsZoneTransferCollector

TlsCollector           (no deps)
DomainWhoisCollector   (no deps)
CrtshCollector         (no deps)
RdapCollector          (no deps)
SubdomainDnsCollector  (no deps)
```

---

## HttpCollector

Fetches the target URL via cURL and captures the full HTTP response.

**Dependencies:** none
**Data class:** `HttpData`

| Field | Type | Description |
|-------|------|-------------|
| `statusCode` | `int` | HTTP response code |
| `headers` | `array<string, list<string>>` | Response headers (lowercased keys) |
| `body` | `string` | Full response body |
| `cookies` | `array<string, string>` | Parsed `Set-Cookie` values |
| `redirectUrl` | `?string` | Effective URL after redirects |
| `responseTime` | `?float` | Total request time (seconds) |
| `httpVersion` | `?int` | cURL HTTP version constant |
| `dnsTime` | `?float` | DNS lookup time |
| `connectTime` | `?float` | TCP connect time |
| `ttfb` | `?float` | Time to first byte |

**Implementation notes:**
- Follows redirects (max 5 hops)
- SSRF protection: `CURLOPT_PROTOCOLS_STR` restricted to `http,https`
- SSL verification enabled
- Timeouts: 15s total, 10s connect
- Configurable User-Agent via `Scavier::setUserAgent()`

---

## HtmlCollector

Parses the HTTP response body into structured DOM elements.

**Dependencies:** `HttpCollector`
**Data class:** `HtmlData`

| Field | Type | Description |
|-------|------|-------------|
| `title` | `?string` | `<title>` text |
| `meta` | `array<string, string>` | `<meta name>` tags |
| `metaProperties` | `array<string, string>` | `<meta property>` tags (OG, Twitter) |
| `scripts` | `array<string>` | External script `src` URLs |
| `inlineScripts` | `array<string>` | Inline `<script>` content |
| `stylesheets` | `array<string>` | Stylesheet `href` URLs |
| `links` | `array<array{rel, href}>` | All `<link>` tags |
| `bodyText` | `string` | Plain text from `<body>` |
| `htmlLang` | `?string` | `<html lang>` attribute |
| `jsonLd` | `list<array>` | Parsed JSON-LD blocks |
| `anchors` | `array<string>` | External `<a>` URLs |
| `emails` | `array<string>` | From `mailto:` links |
| `phones` | `array<string>` | From `tel:` links |

**Helper methods:** `metaTag()`, `hasScriptMatching()`, `scriptsMatching()`, `hasInlineScriptMatching()`

Skips execution if Content-Type is not `text/html` or `application/xhtml`.

---

## DnsCollector

Queries all major DNS record types for the target's hostname.

**Dependencies:** none
**Data class:** `DnsData`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `string` | Queried domain |
| `a` | `array` | A records (IPv4) |
| `aaaa` | `array` | AAAA records (IPv6) |
| `mx` | `array` | MX records (sorted by priority) |
| `ns` | `array` | NS records |
| `txt` | `array` | TXT records (includes `_dmarc` subdomain) |
| `cname` | `array` | CNAME records |
| `soa` | `array` | SOA record |
| `ptr` | `array<string, string>` | Reverse DNS (IP => hostname) |
| `caa` | `array` | CAA records |
| `dnssec` | `bool` | DNSKEY record exists |
| `tlsa` | `array` | TLSA/DANE records |

**Helper methods:** `ips()`, `nameservers()`, `mailExchangers()`, `txtValues()`, `cnameTargets()`, `caaIssuers()`, `hasCaa()`, `hasDnssec()`, `hasTlsa()`

**Implementation notes:**
- Uses `dns_get_record()` for standard record types
- Single batched `dig` subprocess for CAA + DNSKEY + TLSA (optimization over 3 separate calls)
- Domain validated with `/^[a-zA-Z0-9._-]+$/` before subprocess calls
- `proc_open` uses array-form command (no shell interpolation)

---

## DiscoveryCollector

Probes well-known paths and discovers additional pages from footer links, all fetched in parallel.

**Dependencies:** `HttpCollector`
**Data class:** `DiscoveryData`

**Probed paths (30+):**

| Category | Paths |
|----------|-------|
| Standards | `/robots.txt`, `/sitemap.xml`, `/manifest.json`, `/manifest.webmanifest`, `/.well-known/security.txt`, `/favicon.ico`, `/humans.txt` |
| AI readiness | `/llms.txt`, `/.well-known/mcp.json` |
| API discovery | `/openapi.json`, `/swagger.json` |
| Monetization | `/ads.txt` |
| Security exposure | `/.env`, `/.git/HEAD` |
| Business pages | Contact, about, legal, pricing pages (EN + PL variants) |

After probing hardcoded paths, extracts same-domain links from the `<footer>` matching business keywords (contact, pricing, privacy, etc.) and fetches those too.

**Implementation notes:**
- `curl_multi` with 10 concurrent connections
- Per-handle timeout: 5s
- Body stored only if status 200-399 and size < 512KB
- SSRF-safe protocols

**Helper methods:** `exists()`, `body()`, `status()`, `firstHtmlBody()`, `allHtmlBodies()`

---

## TlsCollector

Retrieves TLS certificate details and probes supported protocol versions.

**Dependencies:** none (skips if scheme is not `https`)
**Data class:** `TlsData`

| Field | Type | Description |
|-------|------|-------------|
| `issuer` | `string` | Certificate Authority name |
| `subject` | `string` | Certificate subject CN |
| `san` | `array<string>` | Subject Alternative Names |
| `validFrom` | `string` | Start date (Y-m-d) |
| `validTo` | `string` | End date (Y-m-d) |
| `daysUntilExpiry` | `int` | Days until certificate expires |
| `protocol` | `string` | Negotiated TLS version |
| `cipher` | `string` | Negotiated cipher suite |
| `serialNumber` | `?string` | Certificate serial |
| `ocspStapling` | `bool` | OCSP stapling enabled |
| `supportedProtocols` | `list<string>` | e.g. `['TLSv1.2', 'TLSv1.3']` |
| `certificateChain` | `list<string>` | Subject names from chain |

**Implementation notes:**
- Certificate retrieved via `stream_socket_client()` with `capture_peer_cert`
- `openssl s_client` subprocess for OCSP, chain, and protocol probing
- Minimizes subprocess calls (1-3 calls depending on detected protocols)

---

## WhoisCollector

Runs IP-level WHOIS lookup on the server's first IPv4 address.

**Dependencies:** `DnsCollector`
**Data class:** `WhoisData`

| Field | Type | Description |
|-------|------|-------------|
| `asn` | `?int` | Autonomous System Number |
| `asnName` | `?string` | AS name |
| `netName` | `?string` | Network name |
| `netRange` | `?string` | IP range (CIDR or inetnum) |
| `organization` | `?string` | Hosting organization |
| `country` | `?string` | Country code |
| `abuseContact` | `?string` | Abuse email |
| `rawOutput` | `?string` | Full whois text |

Handles RIPE, ARIN, and APNIC response formats. IP validated with `filter_var()` before subprocess call.

---

## DomainWhoisCollector

Runs domain-level WHOIS lookup for registration details.

**Dependencies:** none
**Data class:** `DomainWhoisData`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `string` | Registrable domain |
| `registrant` | `?string` | Registrant name |
| `registrantOrganization` | `?string` | Registrant organization |
| `registrar` | `?string` | Domain registrar |
| `creationDate` | `?string` | Registration date (Y-m-d) |
| `expirationDate` | `?string` | Expiration date (Y-m-d) |
| `updatedDate` | `?string` | Last update date (Y-m-d) |
| `registrantCountry` | `?string` | Country code |
| `registrantEmail` | `?string` | Contact email |
| `dnssecStatus` | `?string` | DNSSEC status |

GDPR-redacted fields (9 known patterns) are treated as `null`.

---

## CrtshCollector

Queries the crt.sh Certificate Transparency API to discover subdomains.

**Dependencies:** none
**Data class:** `CrtshData`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `string` | Queried domain |
| `certificates` | `list<array>` | Deduplicated certificates (by serial) |
| `subdomains` | `list<string>` | Sorted unique subdomains |

**Helper methods:** `concreteSubdomains()`, `wildcards()`, `issuers()`

Queries `https://crt.sh/?q=%.{domain}&output=json` with 15s timeout.

---

## RdapCollector

Queries the RDAP bootstrap service for structured domain registration data.

**Dependencies:** none
**Data class:** `RdapData`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `string` | Queried domain |
| `registrar` | `?string` | Domain registrar (from vCard) |
| `registrationDate` | `?string` | Registration date (Y-m-d) |
| `expirationDate` | `?string` | Expiration date (Y-m-d) |
| `lastUpdated` | `?string` | Last changed date |
| `status` | `array<string>` | Domain status flags |
| `nameservers` | `array<string>` | Nameservers (lowercased) |

Uses `https://rdap.org/domain/{domain}` which redirects to the correct registry's RDAP server.

---

## SubdomainDnsCollector

Brute-forces DNS resolution for common subdomain prefixes.

**Dependencies:** none
**Data class:** `SubdomainDnsData`

Checks 33+ prefixes: `www`, `mail`, `webmail`, `smtp`, `imap`, `app`, `api`, `cdn`, `static`, `media`, `admin`, `panel`, `cpanel`, `dev`, `staging`, `test`, `beta`, `shop`, `store`, `blog`, `ftp`, `vpn`, `ns1`, `ns2`, `auth`, `login`, `sso`, `docs`, `help`, `status`, `support`, `git`, `ci`, `monitoring`, `autodiscover`, `remote`, `intranet`.

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `string` | Base domain |
| `resolved` | `array<string, array{ip, cname}>` | Subdomains that resolved |
| `failed` | `list<string>` | Subdomains that didn't resolve |

**Helper methods:** `found()`, `count()`

---

## DnsZoneTransferCollector

Attempts AXFR (DNS zone transfer) against each nameserver to detect misconfiguration.

**Dependencies:** `DnsCollector`
**Data class:** `DnsZoneTransferData`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `string` | Target domain |
| `vulnerable` | `bool` | Zone transfer succeeded |
| `vulnerableNameservers` | `list<string>` | NSes that allowed AXFR |
| `records` | `array` | Discovered DNS records per NS |

**Helper methods:** `discoveredHostnames()`

Runs `dig AXFR` per nameserver. Domain and NS hostname validated before subprocess call. 256KB stdout limit.
