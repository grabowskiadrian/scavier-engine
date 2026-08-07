<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\DnsData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class DnsCollector extends Collector
{
    public function execute(Target $target, Context $context): void
    {
        $domain = $target->host();

        if ($domain === null) {
            return;
        }

        $aRecords = $this->query($domain, DNS_A);

        // Single dig call for CAA + DNSKEY + TLSA (was 3 separate calls)
        $digResults = $this->digBatch($domain);

        $context->set(new DnsData(
            domain: $domain,
            a: $aRecords,
            aaaa: $this->query($domain, DNS_AAAA),
            mx: $this->sortMx($this->query($domain, DNS_MX)),
            ns: $this->query($domain, DNS_NS),
            txt: $this->mergeTxt($domain),
            cname: $this->query($domain, DNS_CNAME),
            soa: $this->query($domain, DNS_SOA),
            ptr: $this->resolvePtr($aRecords),
            caa: $digResults['caa'],
            dnssec: $digResults['dnssec'],
            tlsa: $digResults['tlsa'],
        ));
    }

    private function query(string $domain, int $type): array
    {
        $result = @dns_get_record($domain, $type);

        return $result ?: [];
    }

    private function sortMx(array $records): array
    {
        usort($records, fn(array $a, array $b) => ($a['pri'] ?? 99) <=> ($b['pri'] ?? 99));

        return $records;
    }

    /**
     * Merge TXT records and also query _dmarc subdomain.
     */
    private function mergeTxt(string $domain): array
    {
        $txt = $this->query($domain, DNS_TXT);
        $dmarc = $this->query("_dmarc.{$domain}", DNS_TXT);

        return array_merge($txt, $dmarc);
    }

    /**
     * Single dig call for CAA + DNSKEY + TLSA (batch query).
     *
     * @return array{caa: array, dnssec: bool, tlsa: array}
     */
    private function digBatch(string $domain): array
    {
        $result = ['caa' => [], 'dnssec' => false, 'tlsa' => []];

        if (!preg_match('/^[a-zA-Z0-9._-]+$/', $domain)) {
            return $result;
        }

        // dig supports multiple queries in one invocation
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = @proc_open(
            [
                'dig', '+noall', '+answer', '+time=3', '+tries=1',
                $domain, 'CAA',
                $domain, 'DNSKEY',
                "_443._tcp.{$domain}", 'TLSA',
            ],
            $descriptors,
            $pipes,
        );

        if (!is_resource($process)) {
            return $result;
        }

        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1], 64000);
        fclose($pipes[1]);
        fclose($pipes[2]);

        proc_close($process);

        if ($output === false || $output === '') {
            return $result;
        }

        foreach (explode("\n", $output) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, ';')) {
                continue;
            }

            // CAA records
            if (preg_match('/\bCAA\s+(\d+)\s+(\w+)\s+"?([^"]*)"?$/i', $line, $m)) {
                $result['caa'][] = [
                    'flags' => (int) $m[1],
                    'tag' => $m[2],
                    'value' => trim($m[3], '"'),
                ];
            }

            // DNSKEY → DNSSEC configured
            if (str_contains($line, 'DNSKEY')) {
                $result['dnssec'] = true;
            }

            // TLSA records
            if (preg_match('/TLSA\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)/i', $line, $m)) {
                $result['tlsa'][] = [
                    'usage' => (int) $m[1],
                    'selector' => (int) $m[2],
                    'type' => (int) $m[3],
                    'data' => $m[4],
                ];
            }
        }

        return $result;
    }

    /**
     * @return array<string, string> IP => PTR hostname
     */
    private function resolvePtr(array $aRecords): array
    {
        $ptr = [];

        foreach ($aRecords as $record) {
            $ip = $record['ip'] ?? null;

            if ($ip === null) {
                continue;
            }

            $hostname = @gethostbyaddr($ip);

            if ($hostname !== false && $hostname !== $ip) {
                $ptr[$ip] = $hostname;
            }
        }

        return $ptr;
    }
}
