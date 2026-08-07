<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\Data\DnsZoneTransferData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class DnsZoneTransferCollector extends Collector
{
    public static function dependencies(): array
    {
        return [DnsCollector::class];
    }

    public function execute(Target $target, Context $context): void
    {
        $dns = $context->get(DnsData::class);

        if ($dns === null) {
            return;
        }

        $nameservers = $dns->nameservers();

        if ($nameservers === []) {
            return;
        }

        $domain = $dns->domain;
        $vulnerableNs = [];
        $records = [];

        foreach ($nameservers as $ns) {
            $result = $this->attemptAxfr($domain, $ns);

            if ($result !== null) {
                $vulnerableNs[] = $ns;
                $records[$ns] = $result;
            }
        }

        $context->set(new DnsZoneTransferData(
            domain: $domain,
            vulnerable: $vulnerableNs !== [],
            vulnerableNameservers: $vulnerableNs,
            records: $records,
        ));
    }

    /**
     * Attempt AXFR zone transfer using dig.
     *
     * @return array<array{type: string, value: string}>|null Records if transfer succeeded
     */
    private function attemptAxfr(string $domain, string $ns): ?array
    {
        // Validate inputs to prevent command injection
        if (!preg_match('/^[a-zA-Z0-9._-]+$/', $domain) || !preg_match('/^[a-zA-Z0-9._-]+$/', $ns)) {
            return null;
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = @proc_open(
            ['dig', '+time=5', '+tries=1', '@' . $ns, $domain, 'AXFR'],
            $descriptors,
            $pipes,
        );

        if (!is_resource($process)) {
            return null;
        }

        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1], 256000);
        fclose($pipes[1]);
        fclose($pipes[2]);

        proc_close($process);

        if ($output === false || $output === '') {
            return null;
        }

        // Check for transfer failure indicators
        if (str_contains($output, 'Transfer failed')
            || str_contains($output, 'connection refused')
            || str_contains($output, '; Transfer size:') === false) {
            return null;
        }

        return $this->parseAxfrOutput($output, $domain);
    }

    /**
     * @return array<array{type: string, value: string}>
     */
    private function parseAxfrOutput(string $output, string $domain): array
    {
        $records = [];

        foreach (explode("\n", $output) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, ';')) {
                continue;
            }

            // Parse: name TTL IN TYPE value
            if (preg_match('/^(\S+)\s+\d+\s+IN\s+(\w+)\s+(.+)$/', $line, $m)) {
                $name = rtrim($m[1], '.');
                $type = $m[2];
                $value = trim($m[3]);

                // Only include records under our domain
                if ($name === $domain || str_ends_with($name, '.' . $domain)) {
                    $records[] = [
                        'type' => $type,
                        'value' => $name,
                    ];
                }
            }
        }

        return $records;
    }
}
