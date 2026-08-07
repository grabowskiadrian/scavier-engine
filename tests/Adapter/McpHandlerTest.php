<?php

namespace Scavier\Tests\Adapter;

use PHPUnit\Framework\TestCase;
use Scavier\Adapter\McpHandler;
use Scavier\Engine\Scavier;

final class McpHandlerTest extends TestCase
{
    private McpHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new McpHandler(new Scavier());
    }

    public function testInvalidJsonReturnsParseError(): void
    {
        $response = $this->handler->handle('{invalid');

        $this->assertSame('2.0', $response['jsonrpc']);
        $this->assertSame(-32700, $response['error']['code']);
    }

    public function testMissingMethodReturnsInvalidRequest(): void
    {
        $response = $this->handler->handle(json_encode(['id' => 1]));

        $this->assertSame(-32600, $response['error']['code']);
    }

    public function testInitializeReturnsCapabilities(): void
    {
        $response = $this->handler->handle(json_encode([
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'initialize',
        ]));

        $this->assertSame(1, $response['id']);
        $this->assertArrayHasKey('capabilities', $response['result']);
        $this->assertArrayHasKey('serverInfo', $response['result']);
    }

    public function testToolsListReturnsAnalyzeTool(): void
    {
        $response = $this->handler->handle(json_encode([
            'jsonrpc' => '2.0',
            'id' => 2,
            'method' => 'tools/list',
        ]));

        $tools = $response['result']['tools'];
        $this->assertCount(1, $tools);
        $this->assertSame('analyze', $tools[0]['name']);
    }

    public function testNotificationReturnsNull(): void
    {
        $response = $this->handler->handle(json_encode([
            'jsonrpc' => '2.0',
            'method' => 'notifications/initialized',
        ]));

        $this->assertNull($response);
    }

    public function testUnknownMethodReturnsError(): void
    {
        $response = $this->handler->handle(json_encode([
            'jsonrpc' => '2.0',
            'id' => 3,
            'method' => 'unknown/method',
        ]));

        $this->assertSame(-32601, $response['error']['code']);
    }

    public function testToolsCallWithMissingUrl(): void
    {
        $response = $this->handler->handle(json_encode([
            'jsonrpc' => '2.0',
            'id' => 4,
            'method' => 'tools/call',
            'params' => ['name' => 'analyze', 'arguments' => []],
        ]));

        $this->assertTrue($response['result']['isError']);
    }

    public function testToolsCallUnknownTool(): void
    {
        $response = $this->handler->handle(json_encode([
            'jsonrpc' => '2.0',
            'id' => 5,
            'method' => 'tools/call',
            'params' => ['name' => 'unknown', 'arguments' => []],
        ]));

        $this->assertTrue($response['result']['isError']);
    }

    public function testPingReturnsEmptyResult(): void
    {
        $response = $this->handler->handle(json_encode([
            'jsonrpc' => '2.0',
            'id' => 6,
            'method' => 'ping',
        ]));

        $this->assertSame(6, $response['id']);
        $this->assertSame([], $response['result']);
    }
}
