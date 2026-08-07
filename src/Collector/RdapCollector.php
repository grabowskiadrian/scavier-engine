<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\RdapData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class RdapCollector extends Collector
{
    private const BOOTSTRAP_URL = 'https://rdap.org/domain/';

    public function execute(Target $target, Context $context): void
    {
        $host = $target->host();

        if ($host === null) {
            return;
        }

        // Extract registrable domain (last two parts, or three for co.uk etc.)
        $domain = $this->extractDomain($host);

        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => self::BOOTSTRAP_URL . $domain,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 10,
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
            return;
        }

        $data = json_decode($body, true);

        if (!is_array($data)) {
            return;
        }

        $context->set(new RdapData(
            domain: $domain,
            registrar: $this->extractRegistrar($data),
            registrationDate: $this->extractEvent($data, 'registration'),
            expirationDate: $this->extractEvent($data, 'expiration'),
            lastUpdated: $this->extractEvent($data, 'last changed'),
            status: $data['status'] ?? [],
            nameservers: $this->extractNameservers($data),
        ));
    }

    private function extractDomain(string $host): string
    {
        $parts = explode('.', $host);

        // Handle two-part TLDs like co.uk, com.br
        $twoPartTlds = ['co.uk', 'com.br', 'com.au', 'co.jp', 'co.kr', 'com.pl', 'org.uk', 'net.au'];

        if (count($parts) >= 3) {
            $lastTwo = implode('.', array_slice($parts, -2));
            if (in_array($lastTwo, $twoPartTlds, true)) {
                return implode('.', array_slice($parts, -3));
            }
        }

        return implode('.', array_slice($parts, -2));
    }

    private function extractRegistrar(array $data): ?string
    {
        foreach ($data['entities'] ?? [] as $entity) {
            $roles = $entity['roles'] ?? [];

            if (in_array('registrar', $roles, true)) {
                $vcardArray = $entity['vcardArray'] ?? [];

                if (isset($vcardArray[1])) {
                    foreach ($vcardArray[1] as $field) {
                        if (($field[0] ?? '') === 'fn') {
                            return $field[3] ?? null;
                        }
                    }
                }

                return $entity['handle'] ?? null;
            }
        }

        return null;
    }

    private function extractEvent(array $data, string $action): ?string
    {
        foreach ($data['events'] ?? [] as $event) {
            if (($event['eventAction'] ?? '') === $action) {
                $date = $event['eventDate'] ?? null;

                if ($date !== null) {
                    return substr($date, 0, 10); // YYYY-MM-DD
                }
            }
        }

        return null;
    }

    /**
     * @return array<string>
     */
    private function extractNameservers(array $data): array
    {
        $ns = [];

        foreach ($data['nameservers'] ?? [] as $entry) {
            $name = $entry['ldhName'] ?? null;

            if ($name !== null) {
                $ns[] = strtolower($name);
            }
        }

        return $ns;
    }
}
