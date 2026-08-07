<?php

namespace Scavier\Tests\Engine;

use PHPUnit\Framework\TestCase;
use Scavier\Engine\Contract\Collector;
use Scavier\Engine\DependencyResolver;
use Scavier\Engine\Context;
use Scavier\Engine\Target;

final class DependencyResolverTest extends TestCase
{
    private DependencyResolver $resolver;

    protected function setUp(): void
    {
        $this->resolver = new DependencyResolver();
    }

    public function testResolvesWithoutDependencies(): void
    {
        $a = new class extends Collector {
            public function execute(Target $target, Context $context): void {}
        };

        $available = [$a::class => $a];
        $result = $this->resolver->resolve($available, [$a::class]);

        $this->assertCount(1, $result);
        $this->assertSame($a, $result[0]);
    }

    public function testResolvesDependenciesBeforeDependent(): void
    {
        $a = new class extends Collector {
            public function execute(Target $target, Context $context): void {}
        };

        $bDep = $a::class;
        $b = new class($bDep) extends Collector {
            private static string $dep;
            public function __construct(string $dep) { self::$dep = $dep; }
            public static function dependencies(): array { return [self::$dep]; }
            public function execute(Target $target, Context $context): void {}
        };

        $available = [$a::class => $a, $b::class => $b];
        $result = $this->resolver->resolve($available, [$b::class]);

        $this->assertCount(2, $result);
        $this->assertSame($a, $result[0]);
        $this->assertSame($b, $result[1]);
    }

    public function testDetectsCircularDependency(): void
    {
        // Create a collector that depends on itself to trigger circular detection
        $a = new class extends Collector {
            public static function dependencies(): array { return [self::class]; }
            public function execute(Target $target, Context $context): void {}
        };

        $available = [$a::class => $a];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/Circular dependency/');

        $this->resolver->resolve($available, [$a::class]);
    }

    public function testSkipsMissingDependencies(): void
    {
        $a = new class extends Collector {
            public static function dependencies(): array { return ['NonExistent\\Class']; }
            public function execute(Target $target, Context $context): void {}
        };

        $available = [$a::class => $a];
        $result = $this->resolver->resolve($available, [$a::class]);

        $this->assertCount(1, $result);
    }

    public function testDeduplicatesRoots(): void
    {
        $a = new class extends Collector {
            public function execute(Target $target, Context $context): void {}
        };

        $available = [$a::class => $a];
        $result = $this->resolver->resolve($available, [$a::class, $a::class]);

        $this->assertCount(1, $result);
    }
}
