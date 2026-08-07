<?php

namespace Scavier\Collector;

use Scavier\Collector\Data\TlsData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class TlsCollector extends Collector
{
    public function execute(Target $target, Context $context): void
    {
        if ($target->scheme() !== 'https') {
            return;
        }

        $host = $target->host();
        $port = $target->port() ?? 443;

        $streamContext = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => true,
                'verify_peer_name' => true,
                'SNI_enabled' => true,
                'peer_name' => $host,
            ],
        ]);

        $socket = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $streamContext,
        );

        if ($socket === false) {
            return;
        }

        $params = stream_context_get_params($socket);
        $certResource = $params['options']['ssl']['peer_certificate'] ?? null;

        if ($certResource === null) {
            fclose($socket);
            return;
        }

        $cert = openssl_x509_parse($certResource);
        $meta = stream_get_meta_data($socket);

        // Get protocol and cipher from stream
        $cryptoInfo = $meta['crypto'] ?? [];
        $protocol = $cryptoInfo['protocol'] ?? 'unknown';
        $cipher = $cryptoInfo['cipher_name'] ?? 'unknown';

        fclose($socket);

        if ($cert === false) {
            return;
        }

        // Extract issuer
        $issuerParts = $cert['issuer'] ?? [];
        $issuer = $issuerParts['O'] ?? $issuerParts['CN'] ?? 'Unknown';

        // Extract subject
        $subject = $cert['subject']['CN'] ?? $host;

        // Extract SAN
        $san = [];
        $extensions = $cert['extensions'] ?? [];
        if (isset($extensions['subjectAltName'])) {
            foreach (explode(',', $extensions['subjectAltName']) as $entry) {
                $entry = trim($entry);
                if (str_starts_with($entry, 'DNS:')) {
                    $san[] = substr($entry, 4);
                }
            }
        }

        // Validity
        $validFrom = date('Y-m-d', $cert['validFrom_time_t'] ?? 0);
        $validTo = date('Y-m-d', $cert['validTo_time_t'] ?? 0);
        $daysUntilExpiry = (int) round(($cert['validTo_time_t'] - time()) / 86400);

        // Serial
        $serial = $cert['serialNumberHex'] ?? null;

        // Single openssl call for OCSP + chain (was 6 calls, now 1)
        $opensslData = $this->opensslInspect($host, $port);

        $context->set(new TlsData(
            issuer: $issuer,
            subject: $subject,
            san: $san,
            validFrom: $validFrom,
            validTo: $validTo,
            daysUntilExpiry: $daysUntilExpiry,
            protocol: $protocol,
            cipher: $cipher,
            serialNumber: $serial,
            ocspStapling: $opensslData['ocspStapling'],
            supportedProtocols: $opensslData['supportedProtocols'],
            certificateChain: $opensslData['chain'],
        ));
    }

    /**
     * Single openssl s_client call to get OCSP stapling, chain, and protocol info.
     * Replaces 6 separate openssl calls with 1.
     *
     * @return array{ocspStapling: bool, supportedProtocols: list<string>, chain: list<string>}
     */
    private function opensslInspect(string $host, int $port): array
    {
        $result = [
            'ocspStapling' => false,
            'supportedProtocols' => [],
            'chain' => [],
        ];

        // Validate host to prevent command injection
        if (!preg_match('/^[a-zA-Z0-9._-]+$/', $host)) {
            return $result;
        }

        // One call: -status for OCSP, -showcerts for chain
        $output = $this->runOpenssl($host, $port, ['-status', '-showcerts']);

        if ($output === null) {
            return $result;
        }

        // OCSP stapling
        $result['ocspStapling'] = str_contains($output, 'OCSP Response Status: successful');

        // Certificate chain
        if (preg_match_all('/s:(.+)$/m', $output, $subjects)) {
            foreach ($subjects[1] as $subject) {
                $result['chain'][] = trim($subject);
            }
        }

        // Extract protocol from this connection
        if (preg_match('/Protocol\s*:\s*(TLSv[\d.]+)/i', $output, $m)) {
            $negotiated = $m[1];
            // The negotiated protocol is always the highest mutually supported
            // We know 1.2 and 1.3 are the only relevant ones today
            $result['supportedProtocols'][] = $negotiated;

            // If we got TLSv1.3, test if TLSv1.2 is also supported (one extra call)
            if ($negotiated === 'TLSv1.3') {
                $tls12 = $this->runOpenssl($host, $port, ['-tls1_2']);
                if ($tls12 !== null && !str_contains($tls12, ':error:') && str_contains($tls12, 'Protocol')) {
                    array_unshift($result['supportedProtocols'], 'TLSv1.2');
                }
            }

            // Check for legacy TLSv1.0 (one call — only if TLSv1.2 was negotiated, suggesting old server)
            if ($negotiated === 'TLSv1.2') {
                $tls10 = $this->runOpenssl($host, $port, ['-tls1']);
                if ($tls10 !== null && !str_contains($tls10, ':error:') && str_contains($tls10, 'Protocol')) {
                    array_unshift($result['supportedProtocols'], 'TLSv1');
                }
            }
        }

        return $result;
    }

    private function runOpenssl(string $host, int $port, array $extraArgs): ?string
    {
        $args = array_merge(
            ['openssl', 's_client', '-connect', "{$host}:{$port}", '-servername', $host],
            $extraArgs,
        );

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = @proc_open($args, $descriptors, $pipes);

        if (!is_resource($process)) {
            return null;
        }

        fwrite($pipes[0], "Q\n");
        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1], 64000);
        fclose($pipes[1]);
        fclose($pipes[2]);

        proc_close($process);

        return ($output !== false && $output !== '') ? $output : null;
    }
}
