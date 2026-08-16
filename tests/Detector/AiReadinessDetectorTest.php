<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DiscoveryData;
use Scavier\Detector\Seo\RobotsDetector;
use Scavier\Detector\Technology\AiReadinessDetector;
use Scavier\Engine\Context;

final class AiReadinessDetectorTest extends TestCase
{
    public function testDetectsLlmsTxt(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/llms.txt' => ['status' => 200, 'body' => "# My Company\n\nWe build software."]]));
        $context->setDetectorResult(RobotsDetector::class, ['seo' => ['robots' => ['ai_bots' => ['blocks_ai_crawlers' => false, 'blocked' => []]]]]);

        $result = (new AiReadinessDetector())->detect($context);

        $this->assertTrue($result['technology']['ai_readiness']['llms_txt']['exists']);
        $this->assertSame('My Company', $result['technology']['ai_readiness']['llms_txt']['title']);
    }

    public function testDetectsMcpServer(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData(['/.well-known/mcp.json' => ['status' => 200, 'body' => '{"url": "https://example.com/mcp"}']]));
        $context->setDetectorResult(RobotsDetector::class, ['seo' => ['robots' => ['ai_bots' => ['blocks_ai_crawlers' => false, 'blocked' => []]]]]);

        $result = (new AiReadinessDetector())->detect($context);

        $this->assertTrue($result['technology']['ai_readiness']['mcp_server']['exists']);
        $this->assertSame('https://example.com/mcp', $result['technology']['ai_readiness']['mcp_server']['endpoint']);
    }

    public function testReportsAiCrawlerBlocking(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData([]));
        $context->setDetectorResult(RobotsDetector::class, ['seo' => ['robots' => ['ai_bots' => ['blocks_ai_crawlers' => true, 'blocked' => ['GPTBot', 'ClaudeBot']]]]]);

        $result = (new AiReadinessDetector())->detect($context);

        $this->assertTrue($result['technology']['ai_readiness']['ai_crawler_policy']['blocks_ai_crawlers']);
        $this->assertContains('GPTBot', $result['technology']['ai_readiness']['ai_crawler_policy']['blocked_bots']);
    }

    public function testRejectsLlmsTxtWhenHtml(): void
    {
        $html = '<!DOCTYPE html><html><body>Not found</body></html>';

        $context = new Context();
        $context->set(new DiscoveryData(['/llms.txt' => ['status' => 200, 'body' => $html]]));
        $context->setDetectorResult(RobotsDetector::class, ['seo' => ['robots' => ['ai_bots' => ['blocks_ai_crawlers' => false, 'blocked' => []]]]]);

        $result = (new AiReadinessDetector())->detect($context);

        $this->assertFalse($result['technology']['ai_readiness']['llms_txt']['exists']);
    }

    public function testRejectsMcpJsonWhenHtml(): void
    {
        $html = '<!DOCTYPE html><html><body>Redirected</body></html>';

        $context = new Context();
        $context->set(new DiscoveryData(['/.well-known/mcp.json' => ['status' => 200, 'body' => $html]]));
        $context->setDetectorResult(RobotsDetector::class, ['seo' => ['robots' => ['ai_bots' => ['blocks_ai_crawlers' => false, 'blocked' => []]]]]);

        $result = (new AiReadinessDetector())->detect($context);

        $this->assertFalse($result['technology']['ai_readiness']['mcp_server']['exists']);
    }

    public function testRejectsOpenApiWhenHtml(): void
    {
        $html = '<html><body>Login page</body></html>';

        $context = new Context();
        $context->set(new DiscoveryData(['/openapi.json' => ['status' => 200, 'body' => $html]]));
        $context->setDetectorResult(RobotsDetector::class, ['seo' => ['robots' => ['ai_bots' => ['blocks_ai_crawlers' => false, 'blocked' => []]]]]);

        $result = (new AiReadinessDetector())->detect($context);

        $this->assertFalse($result['technology']['ai_readiness']['api_docs']['exists']);
    }

    public function testReportsNoAiFeatures(): void
    {
        $context = new Context();
        $context->set(new DiscoveryData([
            '/llms.txt' => ['status' => 404, 'body' => null],
            '/.well-known/mcp.json' => ['status' => 404, 'body' => null],
            '/openapi.json' => ['status' => 404, 'body' => null],
            '/swagger.json' => ['status' => 404, 'body' => null],
        ]));
        $context->setDetectorResult(RobotsDetector::class, ['seo' => ['robots' => ['ai_bots' => ['blocks_ai_crawlers' => false, 'blocked' => []]]]]);

        $result = (new AiReadinessDetector())->detect($context);

        $this->assertFalse($result['technology']['ai_readiness']['llms_txt']['exists']);
        $this->assertFalse($result['technology']['ai_readiness']['mcp_server']['exists']);
        $this->assertFalse($result['technology']['ai_readiness']['api_docs']['exists']);
    }
}
