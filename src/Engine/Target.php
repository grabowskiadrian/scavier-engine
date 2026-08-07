<?php

namespace Scavier\Engine;

use InvalidArgumentException;

/**
 * The URL being analyzed, with parsed components.
 */
final class Target
{
    private string $url;
    private array $parsed;

    public function __construct(string $url)
    {
        $parsed = parse_url($url);

        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            throw new InvalidArgumentException("Invalid URL: {$url}");
        }

        if (!in_array($parsed['scheme'], ['http', 'https'], true)) {
            throw new InvalidArgumentException("Only http and https URLs are supported: {$url}");
        }

        $ip = gethostbyname($parsed['host']);
        if ($ip !== $parsed['host'] && self::isPrivateIp($ip)) {
            throw new InvalidArgumentException("URL resolves to a private IP address");
        }

        $this->url = $url;
        $this->parsed = $parsed;
    }

    private static function isPrivateIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    public function url(): string
    {
        return $this->url;
    }

    public function scheme(): ?string
    {
        return $this->parsed['scheme'] ?? null;
    }

    public function host(): ?string
    {
        return $this->parsed['host'] ?? null;
    }

    public function domain(): ?string
    {
        return $this->host();
    }

    public function port(): ?int
    {
        return isset($this->parsed['port']) ? (int) $this->parsed['port'] : null;
    }

    public function path(): ?string
    {
        return $this->parsed['path'] ?? null;
    }

    public function query(): ?string
    {
        return $this->parsed['query'] ?? null;
    }
}
