<?php

namespace Scavier\Tests\Adapter;

use PHPUnit\Framework\TestCase;
use Scavier\Adapter\ApiHandler;
use Scavier\Engine\Scavier;

final class ApiHandlerTest extends TestCase
{
    private ApiHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new ApiHandler(new Scavier());
    }

    public function testMissingUrlReturns400(): void
    {
        $response = $this->handler->handle([]);

        $this->assertSame(400, $response['status']);
        $this->assertFalse($response['body']['success']);
        $this->assertArrayHasKey('error', $response['body']);
    }

    public function testEmptyUrlReturns400(): void
    {
        $response = $this->handler->handle(['url' => '']);

        $this->assertSame(400, $response['status']);
        $this->assertFalse($response['body']['success']);
    }

    public function testUnknownDetectorReturns400(): void
    {
        $response = $this->handler->handle([
            'url' => 'https://example.com',
            'detectors' => 'nonexistent',
        ]);

        $this->assertSame(400, $response['status']);
        $this->assertStringContainsString('nonexistent', $response['body']['error']);
    }

    public function testInvalidUrlReturns400(): void
    {
        $response = $this->handler->handle(['url' => 'not-a-url']);

        $this->assertSame(400, $response['status']);
        $this->assertFalse($response['body']['success']);
        $this->assertArrayHasKey('error', $response['body']);
    }

    public function testValidRequestReturnsSuccessEnvelope(): void
    {
        $response = $this->handler->handle(['url' => 'https://example.com']);

        $this->assertSame(200, $response['status']);
        $this->assertTrue($response['body']['success']);
        $this->assertSame('https://example.com', $response['body']['url']);
        $this->assertArrayHasKey('data', $response['body']);
        $this->assertArrayHasKey('_meta', $response['body']['data']);
    }
}
