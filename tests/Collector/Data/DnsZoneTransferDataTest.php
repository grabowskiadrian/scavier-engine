<?php

namespace Scavier\Tests\Collector\Data;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsZoneTransferData;

final class DnsZoneTransferDataTest extends TestCase
{
    public function testVulnerable(): void
    {
        $data = new DnsZoneTransferData(
            domain: 'example.com',
            vulnerable: true,
            vulnerableNameservers: ['ns1.example.com'],
            records: [
                'ns1.example.com' => [
                    ['type' => 'A', 'value' => 'mail.example.com'],
                    ['type' => 'A', 'value' => 'admin.example.com'],
                    ['type' => 'A', 'value' => 'dev.example.com'],
                ],
            ],
        );

        $this->assertTrue($data->vulnerable);
        $this->assertSame(['ns1.example.com'], $data->vulnerableNameservers);

        $hostnames = $data->discoveredHostnames();
        $this->assertContains('mail.example.com', $hostnames);
        $this->assertContains('admin.example.com', $hostnames);
        $this->assertCount(3, $hostnames);
    }

    public function testNotVulnerable(): void
    {
        $data = new DnsZoneTransferData(
            domain: 'example.com',
            vulnerable: false,
        );

        $this->assertFalse($data->vulnerable);
        $this->assertSame([], $data->vulnerableNameservers);
        $this->assertSame([], $data->discoveredHostnames());
    }
}
