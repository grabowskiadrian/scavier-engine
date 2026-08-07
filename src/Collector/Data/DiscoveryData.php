<?php

namespace Scavier\Collector\Data;

final class DiscoveryData
{
    /**
     * @param array<string, array{status: int, body: string|null}> $paths Path => response
     */
    public function __construct(
        public readonly array $paths,
    ) {
    }

    public function exists(string $path): bool
    {
        return isset($this->paths[$path]) && $this->paths[$path]['status'] >= 200 && $this->paths[$path]['status'] < 400;
    }

    public function body(string $path): ?string
    {
        return $this->paths[$path]['body'] ?? null;
    }

    public function status(string $path): ?int
    {
        return $this->paths[$path]['status'] ?? null;
    }

    /**
     * Get the first existing HTML page body from a list of candidate paths.
     */
    public function firstHtmlBody(array $paths): ?string
    {
        foreach ($paths as $path) {
            if ($this->exists($path)) {
                $body = $this->body($path);
                if ($body !== null && str_contains($body, '<')) {
                    return $body;
                }
            }
        }

        return null;
    }

    /**
     * Get all existing HTML page bodies from a list of candidate paths.
     *
     * @return array<string, string> path => body
     */
    public function allHtmlBodies(array $paths): array
    {
        $results = [];

        foreach ($paths as $path) {
            if ($this->exists($path)) {
                $body = $this->body($path);
                if ($body !== null && str_contains($body, '<')) {
                    $results[$path] = $body;
                }
            }
        }

        return $results;
    }
}
