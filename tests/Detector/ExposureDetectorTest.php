<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DiscoveryData;
use Scavier\Collector\Data\DnsZoneTransferData;
use Scavier\Detector\Security\ExposureDetector;
use Scavier\Engine\Context;

final class ExposureDetectorTest extends TestCase
{
    public function testDetectsExposedEnvFile(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/.env' => ['status' => 200, 'body' => "DB_HOST=localhost\nDB_PASS=secret"]]));

        $result = (new ExposureDetector())->detect($context);

        $this->assertSame('/.env', $result['audit']['exposures'][0]['path']);
        $this->assertSame('critical', $result['audit']['exposures'][0]['risk']);
    }

    public function testDetectsExposedGitRepo(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/.git/HEAD' => ['status' => 200, 'body' => 'ref: refs/heads/main']]));

        $result = (new ExposureDetector())->detect($context);

        $this->assertSame('/.git/HEAD', $result['audit']['exposures'][0]['path']);
    }

    public function testIgnoresFalsePositiveEnv(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/.env' => ['status' => 200, 'body' => '<html><body>404 Not Found</body></html>']]));

        $this->assertNull((new ExposureDetector())->detect($context));
    }

    public function testReturnsNullWhenNothingExposed(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData([
            '/.env' => ['status' => 404, 'body' => null],
            '/.git/HEAD' => ['status' => 404, 'body' => null],
        ]));

        $this->assertNull((new ExposureDetector())->detect($context));
    }

    public function testDetectsZoneTransferVulnerability(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData([]));
        $context->set(new DnsZoneTransferData(
            domain: 'example.com',
            vulnerable: true,
            vulnerableNameservers: ['ns1.example.com'],
            records: [
                'ns1.example.com' => [
                    ['type' => 'A', 'value' => 'mail.example.com'],
                    ['type' => 'A', 'value' => 'admin.example.com'],
                ],
            ],
        ));

        $result = (new ExposureDetector())->detect($context);

        $exposures = $result['audit']['exposures'];
        $this->assertCount(1, $exposures);
        $this->assertSame('DNS AXFR', $exposures[0]['path']);
        $this->assertSame('high', $exposures[0]['risk']);
        $this->assertSame(1.0, $exposures[0]['confidence']);
        $this->assertContains('ns1.example.com', $exposures[0]['vulnerable_nameservers']);
        $this->assertSame(2, $exposures[0]['discovered_records']);
    }

    public function testCombinesFileAndZoneTransferExposures(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData([
            '/.env' => ['status' => 200, 'body' => "SECRET=abc"],
        ]));
        $context->set(new DnsZoneTransferData(
            domain: 'example.com',
            vulnerable: true,
            vulnerableNameservers: ['ns1.example.com'],
            records: ['ns1.example.com' => [['type' => 'A', 'value' => 'dev.example.com']]],
        ));

        $result = (new ExposureDetector())->detect($context);

        $this->assertCount(2, $result['audit']['exposures']);
    }
}
