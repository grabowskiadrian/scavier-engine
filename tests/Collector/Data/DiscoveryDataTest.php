<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DiscoveryData;

final class DiscoveryDataTest extends TestCase
{
    public function testExistsForSuccessfulResponse(): void
    {
        $data = new DiscoveryData(['/robots.txt' => ['status' => 200, 'body' => 'User-agent: *']]);
        $this->assertTrue($data->exists('/robots.txt'));
    }

    public function testExistsReturnsFalseFor404(): void
    {
        $data = new DiscoveryData(['/robots.txt' => ['status' => 404, 'body' => null]]);
        $this->assertFalse($data->exists('/robots.txt'));
    }

    public function testExistsReturnsFalseForMissingPath(): void
    {
        $data = new DiscoveryData([]);
        $this->assertFalse($data->exists('/robots.txt'));
    }

    public function testBody(): void
    {
        $data = new DiscoveryData(['/robots.txt' => ['status' => 200, 'body' => 'content']]);
        $this->assertSame('content', $data->body('/robots.txt'));
    }

    public function testStatus(): void
    {
        $data = new DiscoveryData(['/robots.txt' => ['status' => 301, 'body' => null]]);
        $this->assertSame(301, $data->status('/robots.txt'));
    }
}
