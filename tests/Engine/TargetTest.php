<?php

namespace Scavier\Tests\Engine;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Scavier\Engine\Target;

final class TargetTest extends TestCase
{
    public function testParsesFullUrl(): void
    {
        $target = new Target('https://example.com:8080/path?q=1');

        $this->assertSame('https://example.com:8080/path?q=1', $target->url());
        $this->assertSame('https', $target->scheme());
        $this->assertSame('example.com', $target->host());
        $this->assertSame('example.com', $target->domain());
        $this->assertSame(8080, $target->port());
        $this->assertSame('/path', $target->path());
        $this->assertSame('q=1', $target->query());
    }

    public function testParsesSimpleUrl(): void
    {
        $target = new Target('https://example.com');

        $this->assertSame('https', $target->scheme());
        $this->assertSame('example.com', $target->host());
        $this->assertNull($target->port());
        $this->assertNull($target->query());
    }

    public function testRejectsInvalidUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Target('not-a-url');
    }

    public function testRejectsFileProtocol(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Target('file:///etc/passwd');
    }

    public function testRejectsFtpProtocol(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Target('ftp://example.com');
    }

    public function testAcceptsHttp(): void
    {
        $target = new Target('http://example.com');
        $this->assertSame('http', $target->scheme());
    }

    public function testAcceptsHttps(): void
    {
        $target = new Target('https://example.com');
        $this->assertSame('https', $target->scheme());
    }
}
