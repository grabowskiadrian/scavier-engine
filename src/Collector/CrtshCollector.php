<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\CrtshData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class CrtshCollector extends Collector
{
    private const API_URL = 'https://crt.sh/';

    public function execute(Target $target, Context $context): void
    {
        $host = $target->host();

        if ($host === null) {
            return;
        }

        $domain = $this->extractRegistrableDomain($host);
        $data = $this->fetchCertificates($domain);

        if ($data === null) {
            return;
        }

        $subdomains = $this->extractSubdomains($data, $domain);

        $context->set(new CrtshData(
            domain: $domain,
            certificates: $this->normalizeCertificates($data),
            subdomains: $subdomains,
        ));
    }

    private function fetchCertificates(string $domain): ?array
    {
        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => self::API_URL . '?' . http_build_query([
                'q' => '%.' . $domain,
                'output' => 'json',
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT => \Scavier\Engine\Scavier::userAgent(),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_PROTOCOLS_STR => 'https',
            CURLOPT_REDIR_PROTOCOLS_STR => 'https',
        ]);

        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

        curl_close($ch);

        if ($body === false || $status !== 200) {
            return null;
        }

        $data = json_decode($body, true);

        return is_array($data) ? $data : null;
    }

    /**
     * @return list<string>
     */
    private function extractSubdomains(array $certificates, string $domain): array
    {
        $subdomains = [];

        foreach ($certificates as $cert) {
            $nameValue = $cert['name_value'] ?? '';

            // crt.sh returns newline-separated names
            foreach (explode("\n", $nameValue) as $name) {
                $name = strtolower(trim($name));

                if ($name === '' || $name === $domain) {
                    continue;
                }

                // Must be a subdomain of our domain
                if (!str_ends_with($name, '.' . $domain)) {
                    continue;
                }

                if (!in_array($name, $subdomains, true)) {
                    $subdomains[] = $name;
                }
            }
        }

        sort($subdomains);

        return $subdomains;
    }

    /**
     * @return list<array{commonName: string, nameValue: string, issuerName: string, notBefore: string, notAfter: string, serialNumber: string}>
     */
    private function normalizeCertificates(array $data): array
    {
        $seen = [];
        $certs = [];

        foreach ($data as $entry) {
            $serial = $entry['serial_number'] ?? '';

            // Deduplicate by serial number
            if ($serial !== '' && isset($seen[$serial])) {
                continue;
            }

            $seen[$serial] = true;

            $certs[] = [
                'commonName' => $entry['common_name'] ?? '',
                'nameValue' => $entry['name_value'] ?? '',
                'issuerName' => $entry['issuer_name'] ?? '',
                'notBefore' => $entry['not_before'] ?? '',
                'notAfter' => $entry['not_after'] ?? '',
                'serialNumber' => $serial,
            ];
        }

        return $certs;
    }

    private function extractRegistrableDomain(string $host): string
    {
        $parts = explode('.', $host);
        $twoPartTlds = ['co.uk', 'com.br', 'com.au', 'co.jp', 'co.kr', 'com.pl', 'org.uk', 'net.au'];

        if (count($parts) >= 3) {
            $lastTwo = implode('.', array_slice($parts, -2));
            if (in_array($lastTwo, $twoPartTlds, true)) {
                return implode('.', array_slice($parts, -3));
            }
        }

        return implode('.', array_slice($parts, -2));
    }
}
