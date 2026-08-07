<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Technology\ServerDetector;
use Scavier\Engine\Context;

final class ServerDetectorTest extends TestCase
{
    public function testDetectsAndParsesServerHeader(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: ['server' => ['nginx/1.24']],
            body: '',
        ));

        $result = (new ServerDetector())->detect($context);

        $this->assertNotNull($result);
        $this->assertSame('nginx', $result['technology']['web_server']['value']);
        $this->assertSame('1.24', $result['technology']['web_server']['version']);
        $this->assertSame(1.0, $result['technology']['web_server']['confidence']);
    }

    public function testParsesServerWithoutVersion(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: ['server' => ['cloudflare']],
            body: '',
        ));

        $result = (new ServerDetector())->detect($context);

        $this->assertSame('cloudflare', $result['technology']['web_server']['value']);
        $this->assertNull($result['technology']['web_server']['version']);
    }

    public function testDetectsPoweredByHeader(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: ['x-powered-by' => ['PHP/8.3']],
            body: '',
        ));

        $result = (new ServerDetector())->detect($context);

        $this->assertNotNull($result);
        $this->assertSame('PHP/8.3', $result['technology']['runtime']['value']);
    }

    public function testReturnsNullWhenNoHeaders(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: [],
            body: '',
        ));

        $this->assertNull((new ServerDetector())->detect($context));
    }

    public function testReturnsNullWithoutHttpData(): void
    {
        $this->assertNull((new ServerDetector())->detect(new Context()));
    }
}
