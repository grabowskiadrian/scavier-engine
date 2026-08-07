<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\SubdomainDnsData;

final class SubdomainDnsDataTest extends TestCase
{
    public function testFound(): void
    {
        $data = new SubdomainDnsData(
            domain: 'example.com',
            resolved: [
                'mail.example.com' => ['ip' => '93.184.216.34', 'cname' => null],
                'api.example.com' => ['ip' => null, 'cname' => 'api.example.com.cdn.cloudflare.net'],
            ],
        );

        $found = $data->found();
        $this->assertContains('mail.example.com', $found);
        $this->assertContains('api.example.com', $found);
        $this->assertSame(2, $data->count());
    }

    public function testEmpty(): void
    {
        $data = new SubdomainDnsData(domain: 'example.com');

        $this->assertSame([], $data->found());
        $this->assertSame(0, $data->count());
    }
}
