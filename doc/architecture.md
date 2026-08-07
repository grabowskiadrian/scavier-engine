# Architecture

## Pipeline

```
URL input
  |
Target            Validates URL, resolves hostname, SSRF protection
  |
Registry          Auto-discovers all Collectors and Detectors via filesystem scan
  |
DependencyResolver  Topological sort (DFS) of collectors and detectors
  |
Collectors        Run in dependency order, write typed Data objects into Context
  |
Detectors         Run in dependency order, read from Context, return structured arrays
  |
DetectionEngine   Deep-merges all detector results, collects _tags
  |
_meta             scan_duration, timestamp, engine_version, detectors_run, tags
  |
API envelope      {success, data, error}
```

## Key components

### Target (`src/Engine/Target.php`)

Wraps and validates the input URL. Provides SSRF protection:

- Only `http` and `https` schemes accepted
- Hostname resolved via `gethostbyname()` — rejects private/reserved IPs (`FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`)
- All cURL calls use `CURLOPT_PROTOCOLS_STR => 'http,https'` and `CURLOPT_REDIR_PROTOCOLS_STR => 'http,https'`

### Registry (`src/Engine/Registry.php`)

Auto-discovers collectors and detectors by scanning `src/Collector/` and `src/Detector/` with `RecursiveDirectoryIterator`. No manual registration needed — drop a PHP class in the right directory and it's available instantly.

### DependencyResolver (`src/Engine/DependencyResolver.php`)

Resolves execution order for both collectors and detectors using topological sort (DFS). Both collectors and detectors can declare dependencies:

- **Collector dependencies** — other collectors that must run first (e.g., `HtmlCollector` depends on `HttpCollector`)
- **Detector dependencies** — collectors or other detectors (e.g., `SeoDetector` depends on `RobotsDetector` and `SitemapDetector`)

### Context (`src/Engine/Context.php`)

Shared data store. Collectors write typed Data objects (e.g., `HttpData`, `DnsData`) via `$context->set()`. Detectors read them via `$context->get(HttpData::class)`.

### DetectionEngine (`src/Engine/DetectionEngine.php`)

Orchestrates the full pipeline:

1. Resolves collector dependencies, runs collectors in order
2. Resolves detector dependencies, runs detectors in order
3. Deep-merges all detector output arrays
4. Strips `_tags` from each detector result and collects them into `_meta.tags`
5. Adds `_meta` section

### Scavier (`src/Engine/Scavier.php`)

Main entry point. Wraps Registry + DetectionEngine + DependencyResolver.

```php
$scavier = new Scavier();

// Analyze with all detectors
$result = $scavier->analyze('https://example.com');

// Analyze with specific detectors (pass FQCN array)
$result = $scavier->analyze('https://example.com', $detectors);

// List available detectors
$detectors = $scavier->availableDetectors(); // ['server' => FQCN, ...]
```

## Output structure

Results are organized into 8 categories plus an audit section:

```
technology/         CMS, frameworks, libraries, server, fonts, PWA, ecommerce, etc.
infrastructure/     CDN, hosting, DNS, mail, performance, subdomains, etc.
domain/             SSL certificate, registration, DNS security
security/           Headers, cookies, TLS, email auth, security.txt
business/           Company info, contacts, social profiles
content/            Language, accessibility, feeds
marketing/          Analytics, CRM, chat, ads, A/B testing, consent
seo/                Robots, sitemap, SEO audit
audit/              Security score, SEO score, SSL issues, exposures
_meta/              Scan metadata, tags
```

### The `_tags` system

Any detector can include `'_tags' => ['WordPress', 'PHP']` in its return array. These are automatically:

1. Stripped from the detector output before merging
2. Collected, deduplicated, and sorted
3. Placed in `_meta.tags` as a flat array of all technology/service names found

This gives API consumers a quick summary of everything detected without traversing the full result tree.

### The `audit` section

Cross-cutting concerns aggregated from multiple detectors:

| Key | Source detector | Content |
|-----|----------------|---------|
| `security_score` | SecurityHeadersDetector | Score, grade (A-F), present/total count |
| `seo_score` | SeoDetector | Score, passed/total |
| `ssl_issues` | SslCertificateDetector | Expired, expiring, legacy TLS |
| `exposures` | ExposureDetector | .env, .git/HEAD, zone transfer |

## Adapters

### REST API (`src/Adapter/Http.php`, `src/Adapter/ApiHandler.php`)

- Endpoint: `GET /analyze?url=...&detectors=...`
- Rate limit: 30 requests/minute per IP (temp file based)
- CORS: `Access-Control-Allow-Origin: *`
- Error responses: HTTP 400 (bad URL, unknown detector) or 429 (rate limit)

### MCP Server (`src/Adapter/McpHandler.php`)

- Endpoint: `POST /mcp`
- Protocol: JSON-RPC 2.0, MCP version `2024-11-05`
- Exposes single tool `analyze` with params `url` (required) and `detectors` (optional)
- Methods: `initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping`
- Request body limit: 64 KB

### Web UI (`templates/docs.php`)

Interactive homepage at `/` with chip-based detector picker. Toggle detectors by category, see descriptions and required collectors in tooltips, fire API requests directly from the browser.

## Project structure

```
src/
  Adapter/            HTTP routing, API handler, MCP handler
  Collector/          Data collectors (11 classes)
  Collector/Data/     Typed data objects (HttpData, DnsData, etc.)
  Detector/           Knowledge detectors (44 classes, organized by category)
    Business/         Company, Contact, Social
    Content/          Accessibility, Feed, Language
    Infrastructure/   Cache, CDN, Compression, DNS, Hosting, etc.
    Marketing/        AbTesting, AdNetwork, AdsTxt, Chat, Consent, CRM
    Security/         Cookie, DnsSecurity, EmailSecurity, Exposure, etc.
    Seo/              Robots, Seo, Sitemap
    Technology/       AiReadiness, Analytics, CMS, Ecommerce, etc.
  Engine/             Core: Registry, DependencyResolver, DetectionEngine, Context, Target
  Engine/Contract/    Collector/Detector base classes and interfaces
templates/            Built-in web UI
public/               Web entry point (index.php)
tests/                PHPUnit tests
doc/                  Documentation
```

## Security model

- **SSRF protection** — private IP rejection + protocol restriction on all cURL calls
- **Input validation** — domains/IPs validated before subprocess calls (`/^[a-zA-Z0-9._-]+$/` or `filter_var`)
- **No shell injection** — all `proc_open` calls use array-form commands
- **Output limits** — stdout capped at 64-256KB per subprocess
- **Rate limiting** — 30 req/min per IP on the HTTP adapter
- **No API keys** — self-hosted, zero external service accounts required
