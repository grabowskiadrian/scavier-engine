<?php

namespace Scavier\Detector\Security;

use Scavier\Collector\Data\TlsData;
use Scavier\Collector\TlsCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class SslCertificateDetector extends Detector
{
    private const KNOWN_ISSUERS = [
        "Let's Encrypt" => '/Let\'s Encrypt/i',
        'DigiCert' => '/DigiCert/i',
        'Sectigo' => '/Sectigo|Comodo|COMODO/i',
        'GlobalSign' => '/GlobalSign/i',
        'GoDaddy' => '/GoDaddy|Starfield/i',
        'Amazon' => '/Amazon/i',
        'Google Trust Services' => '/Google Trust Services/i',
        'Cloudflare' => '/Cloudflare/i',
        'ZeroSSL' => '/ZeroSSL/i',
        'Buypass' => '/Buypass/i',
    ];

    public static function dependencies(): array
    {
        return [TlsCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $tls = $context->get(TlsData::class);

        if ($tls === null) {
            return null;
        }

        $issuerName = $tls->issuer;
        foreach (self::KNOWN_ISSUERS as $name => $pattern) {
            if (preg_match($pattern, $tls->issuer)) {
                $issuerName = $name;
                break;
            }
        }

        $hasWildcard = !empty(array_filter($tls->san, fn(string $s) => str_starts_with($s, '*.')));
        $baseDomains = array_unique(array_map(fn(string $s) => preg_replace('/^\*\./', '', $s), $tls->san));
        $isMultiDomain = count($baseDomains) > 1;

        // domain.ssl — certificate facts
        $ssl = [
            'issuer' => $issuerName,
            'subject' => $tls->subject,
            'valid_from' => $tls->validFrom,
            'valid_to' => $tls->validTo,
            'days_until_expiry' => $tls->daysUntilExpiry,
            'san' => $tls->san,
            'san_count' => count($tls->san),
            'wildcard' => $hasWildcard,
            'multi_domain' => $isMultiDomain,
            'confidence' => 1.0,
            'evidence' => 'TLS certificate inspection',
        ];

        if ($tls->serialNumber !== null) {
            $ssl['serial_number'] = $tls->serialNumber;
        }

        if ($tls->certificateChain !== []) {
            $ssl['certificate_chain'] = $tls->certificateChain;
            $ssl['chain_length'] = count($tls->certificateChain);
        }

        // security.tls — connection configuration
        $tlsConfig = [
            'protocol' => $tls->protocol,
            'cipher' => $tls->cipher,
            'ocsp_stapling' => $tls->ocspStapling,
            'confidence' => 1.0,
            'evidence' => 'TLS connection inspection',
        ];

        if ($tls->supportedProtocols !== []) {
            $tlsConfig['supported_protocols'] = $tls->supportedProtocols;
        }

        // audit.ssl_issues — problems
        $issues = [];

        if ($tls->daysUntilExpiry <= 0) {
            $issues[] = [
                'severity' => 'critical',
                'issue' => 'certificate_expired',
                'description' => 'SSL certificate has expired',
                'evidence' => "Expired {$tls->validTo}",
            ];
        } elseif ($tls->daysUntilExpiry <= 30) {
            $issues[] = [
                'severity' => 'warning',
                'issue' => 'certificate_expiring_soon',
                'description' => "SSL certificate expires in {$tls->daysUntilExpiry} days",
                'evidence' => "Expires {$tls->validTo}",
            ];
        }

        if ($tls->supportedProtocols !== []) {
            $legacy = array_intersect($tls->supportedProtocols, ['TLSv1', 'TLSv1.1']);
            if ($legacy !== []) {
                $issues[] = [
                    'severity' => 'warning',
                    'issue' => 'legacy_tls_protocols',
                    'description' => 'Server supports deprecated TLS versions',
                    'protocols' => array_values($legacy),
                    'evidence' => 'Deprecated: ' . implode(', ', $legacy),
                ];
            }
        }

        $result = [
            'domain' => ['ssl' => $ssl],
            'security' => ['tls' => $tlsConfig],
        ];

        if ($issues !== []) {
            $result['audit'] = ['ssl_issues' => $issues];
        }

        $result['_tags'] = [$issuerName];

        return $result;
    }
}
