<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\DnsData;
use Scavier\Collector\Data\WhoisData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class WhoisCollector extends Collector
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

        $ips = $dns->ips();

        if ($ips === []) {
            return;
        }

        // Use the first IPv4 address for whois lookup
        $ip = $this->firstIpv4($ips);

        if ($ip === null) {
            return;
        }

        $output = $this->runWhois($ip);

        if ($output === null) {
            return;
        }

        $context->set(new WhoisData(
            asn: $this->extractAsn($output),
            asnName: $this->extractField($output, ['as-name', 'aut-num', 'ASName']),
            netName: $this->extractField($output, ['netname', 'NetName']),
            netRange: $this->extractField($output, ['inetnum', 'NetRange', 'CIDR']),
            organization: $this->extractField($output, ['org-name', 'OrgName', 'Organization', 'descr']),
            country: $this->extractField($output, ['country', 'Country']),
            abuseContact: $this->extractAbuseEmail($output),
            rawOutput: $output,
        ));
    }

    private function firstIpv4(array $ips): ?string
    {
        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $ip;
            }
        }

        return null;
    }

    private function runWhois(string $ip): ?string
    {
        // Validate IP to prevent command injection
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = @proc_open(
            ['whois', $ip],
            $descriptors,
            $pipes,
        );

        if (!is_resource($process)) {
            return null;
        }

        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1], 64000);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        if ($exitCode !== 0 || $output === false || $output === '') {
            return null;
        }

        return $output;
    }

    private function extractField(string $output, array $fieldNames): ?string
    {
        foreach ($fieldNames as $field) {
            if (preg_match('/^' . preg_quote($field, '/') . ':\s*(.+)$/mi', $output, $m)) {
                return trim($m[1]);
            }
        }

        return null;
    }

    private function extractAsn(string $output): ?int
    {
        // Match "origin: AS12345" or "OriginAS: AS12345"
        if (preg_match('/(?:origin|OriginAS):\s*AS?(\d+)/mi', $output, $m)) {
            return (int) $m[1];
        }

        return null;
    }

    private function extractAbuseEmail(string $output): ?string
    {
        // Look for abuse email in various formats
        if (preg_match('/(?:OrgAbuseEmail|abuse-mailbox|% Abuse contact for .+ is \'):\s*([^\s\n\']+@[^\s\n\']+)/mi', $output, $m)) {
            return trim($m[1]);
        }

        // Fallback: "% Abuse contact for '...' is '...'"
        if (preg_match("/Abuse contact for .+ is '([^']+@[^']+)'/i", $output, $m)) {
            return trim($m[1]);
        }

        return null;
    }
}
