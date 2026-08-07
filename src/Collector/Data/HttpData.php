<?php

namespace Scavier\Collector\Data;

final class HttpData
{
    /**
     * @param array<string, list<string>> $headers Lowercased header names, each with a list of values
     * @param array<string, string> $cookies
     */
    public function __construct(
        public readonly int $statusCode,
        public readonly array $headers,
        public readonly string $body,
        public readonly array $cookies = [],
        public readonly ?string $redirectUrl = null,
        public readonly ?float $responseTime = null,
        public readonly ?int $httpVersion = null,
        public readonly ?float $dnsTime = null,
        public readonly ?float $connectTime = null,
        public readonly ?float $ttfb = null,
    ) {
    }

    /**
     * Get the last value for a header (most common use case).
     */
    public function header(string $name): ?string
    {
        $values = $this->headers[strtolower($name)] ?? null;

        return $values !== null ? end($values) : null;
    }

    /**
     * Get all values for a header.
     *
     * @return list<string>
     */
    public function headerAll(string $name): array
    {
        return $this->headers[strtolower($name)] ?? [];
    }
}
