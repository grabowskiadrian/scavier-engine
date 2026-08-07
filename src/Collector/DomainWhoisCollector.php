<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\DomainWhoisData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class DomainWhoisCollector extends Collector
{
    public function execute(Target $target, Context $context): void
    {
        $host = $target->host();

        if ($host === null) {
            return;
        }

        $domain = $this->extractRegistrableDomain($host);
        $output = $this->runWhois($domain);

        if ($output === null) {
            return;
        }

        $context->set(new DomainWhoisData(
            domain: $domain,
            registrant: $this->extractField($output, [
                'Registrant Name', 'registrant', 'holder',
                'Registrant Organization', 'org',
            ]),
            registrantOrganization: $this->extractField($output, [
                'Registrant Organization', 'Registrant Org',
                'org-name', 'organization',
            ]),
            registrar: $this->extractField($output, [
                'Registrar', 'Sponsoring Registrar',
                'registrar', 'Registrar Name',
            ]),
            creationDate: $this->extractDate($output, [
                'Creation Date', 'Created Date', 'created',
                'Registration Date', 'registered', 'Created On',
                'Domain Registration Date',
            ]),
            expirationDate: $this->extractDate($output, [
                'Registry Expiry Date', 'Expiration Date', 'expires',
                'Expiry Date', 'paid-till', 'Registrar Registration Expiration Date',
                'renewal date', 'Domain Expiration Date',
            ]),
            updatedDate: $this->extractDate($output, [
                'Updated Date', 'Last Updated', 'last-modified',
                'Last Modified', 'changed', 'modified',
            ]),
            registrantCountry: $this->extractField($output, [
                'Registrant Country', 'Registrant State/Province',
                'country',
            ]),
            registrantEmail: $this->extractEmail($output),
            dnssecStatus: $this->extractField($output, [
                'DNSSEC', 'dnssec',
            ]),
            rawOutput: $output,
        ));
    }

    private function runWhois(string $domain): ?string
    {
        // Validate domain to prevent command injection
        if (!preg_match('/^[a-zA-Z0-9._-]+$/', $domain)) {
            return null;
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = @proc_open(
            ['whois', $domain],
            $descriptors,
            $pipes,
        );

        if (!is_resource($process)) {
            return null;
        }

        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1], 128000);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        if ($output === false || $output === '') {
            return null;
        }

        // Some whois servers return exit code 1 but still provide data
        return $output;
    }

    private function extractField(string $output, array $fieldNames): ?string
    {
        foreach ($fieldNames as $field) {
            if (preg_match('/^' . preg_quote($field, '/') . ':\s*(.+)$/mi', $output, $m)) {
                $value = trim($m[1]);
                if ($value !== '' && !$this->isRedacted($value)) {
                    return $value;
                }
            }
        }

        return null;
    }

    private function extractDate(string $output, array $fieldNames): ?string
    {
        foreach ($fieldNames as $field) {
            if (preg_match('/^' . preg_quote($field, '/') . ':\s*(.+)$/mi', $output, $m)) {
                $value = trim($m[1]);
                if ($value !== '') {
                    // Try to normalize to Y-m-d
                    $timestamp = @strtotime($value);
                    if ($timestamp !== false) {
                        return date('Y-m-d', $timestamp);
                    }

                    return $value;
                }
            }
        }

        return null;
    }

    private function extractEmail(string $output): ?string
    {
        $fields = ['Registrant Email', 'Admin Email', 'Tech Email', 'e-mail'];

        foreach ($fields as $field) {
            if (preg_match('/^' . preg_quote($field, '/') . ':\s*(\S+@\S+)$/mi', $output, $m)) {
                $email = trim($m[1]);
                if (!$this->isRedacted($email)) {
                    return $email;
                }
            }
        }

        return null;
    }

    private function isRedacted(string $value): bool
    {
        $redactedPatterns = [
            'REDACTED', 'redacted', 'not disclosed',
            'Data Protected', 'GDPR', 'Privacy', 'Whois Privacy',
            'Contact Privacy', 'Identity Protection',
            'is not available', 'Not Disclosed',
        ];

        foreach ($redactedPatterns as $pattern) {
            if (stripos($value, $pattern) !== false) {
                return true;
            }
        }

        return false;
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
