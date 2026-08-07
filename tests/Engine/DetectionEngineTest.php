<?php

namespace Scavier\Tests\Engine;

use PHPUnit\Framework\TestCase;
use Scavier\Engine\Context;
use Scavier\Engine\DependencyResolver;
use Scavier\Engine\Registry;
use Scavier\Engine\DetectionEngine;
use Scavier\Engine\Target;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\Contract\Detector;

final class DetectionEngineTest extends TestCase
{
    private function buildEngine(array $collectors, array $detectors): DetectionEngine
    {
        $registry = new Registry();

        foreach ($collectors as $collector) {
            $registry->addCollector($collector);
        }

        foreach ($detectors as $detector) {
            $registry->addDetector($detector);
        }

        return new DetectionEngine($registry, new DependencyResolver());
    }

    public function testRunsCollectorThenDetector(): void
    {
        $log = [];

        $collector = new class($log) extends Collector {
            private array $log;
            public function __construct(array &$log) { $this->log = &$log; }
            public function execute(Target $target, Context $context): void {
                $this->log[] = 'collector';
                $context->set((object) ['data' => 'test']);
            }
        };

        $collectorClass = $collector::class;

        $detector = new class($log, $collectorClass) extends Detector {
            private array $log;
            private static string $dep;
            public function __construct(array &$log, string $dep) { $this->log = &$log; self::$dep = $dep; }
            public static function dependencies(): array { return [self::$dep]; }
            public function detect(Context $context): ?array {
                $this->log[] = 'detector';
                return ['test' => ['found' => true]];
            }
        };

        $engine = $this->buildEngine([$collector], [$detector]);
        $result = $engine->analyze(new Target('https://example.com'), [$detector::class]);

        $this->assertSame(['collector', 'detector'], $log);
        $this->assertTrue($result['test']['found']);
        $this->assertArrayHasKey('_meta', $result);
        $this->assertArrayHasKey('scan_duration', $result['_meta']);
        $this->assertArrayHasKey('timestamp', $result['_meta']);
        $this->assertArrayHasKey('engine_version', $result['_meta']);
        $this->assertArrayHasKey('detectors_run', $result['_meta']);
    }

    public function testDetectorReturningNullIsSkipped(): void
    {
        $detector = new class extends Detector {
            public function detect(Context $context): ?array { return null; }
        };

        $engine = $this->buildEngine([], [$detector]);
        $result = $engine->analyze(new Target('https://example.com'), [$detector::class]);

        // Only _meta should be present
        $this->assertArrayHasKey('_meta', $result);
        $this->assertSame(['_meta'], array_keys($result));
    }

    public function testMultipleDetectorsSameCategoryMergesCorrectly(): void
    {
        $detectorA = new class extends Detector {
            public function detect(Context $context): ?array {
                return ['technology' => ['server' => ['value' => 'nginx']]];
            }
        };

        $detectorB = new class extends Detector {
            public function detect(Context $context): ?array {
                return ['technology' => ['runtime' => ['value' => 'PHP']]];
            }
        };

        $engine = $this->buildEngine([], [$detectorA, $detectorB]);
        $result = $engine->analyze(
            new Target('https://example.com'),
            [$detectorA::class, $detectorB::class]
        );

        $this->assertSame('nginx', $result['technology']['server']['value']);
        $this->assertSame('PHP', $result['technology']['runtime']['value']);
    }

    public function testEmptyRequestedDetectorsReturnsOnlyMeta(): void
    {
        $engine = $this->buildEngine([], []);
        $result = $engine->analyze(new Target('https://example.com'), []);

        $this->assertSame(['_meta'], array_keys($result));
        $this->assertSame([], $result['_meta']['detectors_run']);
    }

    public function testCollectsTagsFromDetectors(): void
    {
        $detectorA = new class extends Detector {
            public function detect(Context $context): ?array {
                return ['technology' => ['cms' => 'WordPress'], '_tags' => ['WordPress']];
            }
        };

        $detectorB = new class extends Detector {
            public function detect(Context $context): ?array {
                return ['infrastructure' => ['hosting' => 'Hetzner'], '_tags' => ['Hetzner', 'nginx']];
            }
        };

        $engine = $this->buildEngine([], [$detectorA, $detectorB]);
        $result = $engine->analyze(
            new Target('https://example.com'),
            [$detectorA::class, $detectorB::class]
        );

        $tags = $result['_meta']['tags'];
        $this->assertContains('WordPress', $tags);
        $this->assertContains('Hetzner', $tags);
        $this->assertContains('nginx', $tags);
        // Tags should be sorted
        $this->assertSame($tags, array_values(array_unique($tags)));
        // _tags should NOT appear in result categories
        $this->assertArrayNotHasKey('_tags', $result);
    }

    public function testDeduplicatesTags(): void
    {
        $detectorA = new class extends Detector {
            public function detect(Context $context): ?array {
                return ['a' => [], '_tags' => ['Cloudflare']];
            }
        };

        $detectorB = new class extends Detector {
            public function detect(Context $context): ?array {
                return ['b' => [], '_tags' => ['Cloudflare', 'nginx']];
            }
        };

        $engine = $this->buildEngine([], [$detectorA, $detectorB]);
        $result = $engine->analyze(
            new Target('https://example.com'),
            [$detectorA::class, $detectorB::class]
        );

        $this->assertCount(2, $result['_meta']['tags']);
    }

    public function testDeepMergePreservesNestedKeys(): void
    {
        $detectorA = new class extends Detector {
            public function detect(Context $context): ?array {
                return ['technology' => ['libraries' => [['value' => 'jQuery']]]];
            }
        };

        $detectorB = new class extends Detector {
            public function detect(Context $context): ?array {
                return ['technology' => ['frameworks' => [['value' => 'React']]]];
            }
        };

        $engine = $this->buildEngine([], [$detectorA, $detectorB]);
        $result = $engine->analyze(
            new Target('https://example.com'),
            [$detectorA::class, $detectorB::class]
        );

        $this->assertSame('jQuery', $result['technology']['libraries'][0]['value']);
        $this->assertSame('React', $result['technology']['frameworks'][0]['value']);
    }
}
