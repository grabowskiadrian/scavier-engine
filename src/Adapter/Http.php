<?php

namespace Scavier\Adapter;

use Scavier\Engine\Scavier;

final class Http
{
    private const RATE_LIMIT = 30; // requests per minute
    private const RATE_WINDOW = 60; // seconds

    public static function serve(): never
    {
        $scavier = new Scavier();
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

        match ($path) {
            '/' => self::handleDocs($scavier),
            '/analyze' => self::handleApi($scavier),
            '/mcp' => self::handleMcp($scavier),
            default => self::handleNotFound(),
        };

        exit;
    }

    private static function handleDocs(Scavier $scavier): void
    {
        $allDetectors = $scavier->availableDetectors();
        $detectors = array_keys($allDetectors);

        $categories = [];
        foreach ($allDetectors as $short => $fqcn) {
            $parts = explode('\\', $fqcn);
            $category = $parts[count($parts) - 2] ?? 'Other';
            $categories[$category][] = $short;
        }
        ksort($categories);

        $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost:8000';
        $baseUrl = $scheme . '://' . $host;

        header('Content-Type: text/html; charset=utf-8');
        require __DIR__ . '/../../templates/docs.php';
    }

    private static function handleApi(Scavier $scavier): void
    {
        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
            http_response_code(204);
            return;
        }

        if (!self::checkRateLimit()) {
            http_response_code(429);
            echo json_encode(['error' => 'Rate limit exceeded. Try again later.']);
            return;
        }

        $handler = new ApiHandler($scavier);
        $response = $handler->handle($_GET);

        http_response_code($response['status']);
        echo json_encode($response['body'], JSON_PRETTY_PRINT);
    }

    private static function handleMcp(Scavier $scavier): void
    {
        header('Content-Type: application/json');

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST.']);
            return;
        }

        if (!self::checkRateLimit()) {
            http_response_code(429);
            echo json_encode(['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32000, 'message' => 'Rate limit exceeded']]);
            return;
        }

        $handler = new McpHandler($scavier);
        $input = file_get_contents('php://input');

        if (strlen($input) > 65536) {
            http_response_code(413);
            echo json_encode(['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32600, 'message' => 'Request too large']]);
            return;
        }

        $response = $handler->handle($input);

        if ($response === null) {
            http_response_code(204);
            return;
        }

        echo json_encode($response);
    }

    private static function handleNotFound(): void
    {
        header('Content-Type: application/json');
        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
    }

    private static function checkRateLimit(): bool
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $file = sys_get_temp_dir() . '/scavier_rate_' . md5($ip);

        $now = time();
        $requests = [];

        if (file_exists($file)) {
            $data = @file_get_contents($file);
            if ($data !== false) {
                $requests = json_decode($data, true) ?: [];
            }
        }

        // Remove expired entries
        $requests = array_values(array_filter($requests, fn(int $t) => $t > $now - self::RATE_WINDOW));

        if (count($requests) >= self::RATE_LIMIT) {
            return false;
        }

        $requests[] = $now;
        @file_put_contents($file, json_encode($requests));

        return true;
    }
}
