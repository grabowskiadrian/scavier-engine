<?php

namespace Scavier\Collector;

use RuntimeException;
use Scavier\Collector\Data\HttpData;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Target;

class HttpCollector extends Collector
{
    public function execute(Target $target, Context $context): void
    {
        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => $target->url(),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT => \Scavier\Engine\Scavier::userAgent(),
            CURLOPT_HEADER => false,
            CURLOPT_ENCODING => '',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_PROTOCOLS_STR => 'http,https',
            CURLOPT_REDIR_PROTOCOLS_STR => 'http,https',
        ]);

        $headers = [];
        $cookies = [];

        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($ch, string $line) use (&$headers, &$cookies) {
            $len = strlen($line);
            $parts = explode(':', $line, 2);

            if (count($parts) === 2) {
                $name = strtolower(trim($parts[0]));
                $value = trim($parts[1]);
                $headers[$name][] = $value;

                if ($name === 'set-cookie') {
                    $cookieParts = explode('=', explode(';', $value)[0], 2);
                    if (count($cookieParts) === 2) {
                        $cookies[trim($cookieParts[0])] = trim($cookieParts[1]);
                    }
                }
            }

            return $len;
        });

        $startTime = microtime(true);
        $body = curl_exec($ch);
        $responseTime = microtime(true) - $startTime;

        if ($body === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException("HTTP request failed: {$error}");
        }

        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $httpVersion = curl_getinfo($ch, CURLINFO_HTTP_VERSION);
        $dnsTime = curl_getinfo($ch, CURLINFO_NAMELOOKUP_TIME);
        $connectTime = curl_getinfo($ch, CURLINFO_CONNECT_TIME);
        $ttfb = curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME);

        curl_close($ch);

        $redirectUrl = ($effectiveUrl !== $target->url()) ? $effectiveUrl : null;

        $context->set(new HttpData(
            statusCode: $statusCode,
            headers: $headers,
            body: $body,
            cookies: $cookies,
            redirectUrl: $redirectUrl,
            responseTime: round($responseTime, 3),
            httpVersion: $httpVersion ?: null,
            dnsTime: $dnsTime ? round($dnsTime, 3) : null,
            connectTime: $connectTime ? round($connectTime, 3) : null,
            ttfb: $ttfb ? round($ttfb, 3) : null,
        ));
    }
}
