<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HttpData;

final class HttpDataTest extends TestCase
{
    public function testHeaderReturnsLastValue(): void
    {
        $data = new HttpData(
            statusCode: 200,
            headers: [
                'content-type' => ['text/html'],
                'x-powered-by' => ['PHP/8.3'],
            ],
            body: '<html></html>',
        );

        $this->assertSame('text/html', $data->header('Content-Type'));
        $this->assertSame('PHP/8.3', $data->header('X-Powered-By'));
        $this->assertNull($data->header('X-Missing'));
    }

    public function testHeaderAllReturnsAllValues(): void
    {
        $data = new HttpData(
            statusCode: 200,
            headers: [
                'set-cookie' => ['session=abc', 'theme=dark'],
            ],
            body: '',
        );

        $this->assertSame(['session=abc', 'theme=dark'], $data->headerAll('Set-Cookie'));
        $this->assertSame([], $data->headerAll('X-Missing'));
    }

    public function testHeaderReturnsLastWhenMultiple(): void
    {
        $data = new HttpData(
            statusCode: 200,
            headers: [
                'set-cookie' => ['first', 'second', 'third'],
            ],
            body: '',
        );

        $this->assertSame('third', $data->header('Set-Cookie'));
    }

    public function testProperties(): void
    {
        $data = new HttpData(
            statusCode: 301,
            headers: [],
            body: '',
            cookies: ['session' => 'abc123'],
            redirectUrl: 'https://example.com/',
            responseTime: 0.123,
        );

        $this->assertSame(301, $data->statusCode);
        $this->assertSame(['session' => 'abc123'], $data->cookies);
        $this->assertSame('https://example.com/', $data->redirectUrl);
        $this->assertSame(0.123, $data->responseTime);
    }
}
