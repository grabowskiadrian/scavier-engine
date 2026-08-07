<?php

namespace Scavier\Tests\Engine;

use PHPUnit\Framework\TestCase;
use Scavier\Engine\Registry;

final class RegistryTest extends TestCase
{
    public function testBuildDiscoversCollectorsAndDetectors(): void
    {
        $registry = Registry::build();

        $this->assertNotEmpty($registry->collectors(), 'Should discover at least one collector');
        $this->assertNotEmpty($registry->detectors(), 'Should discover at least one detector');
    }

    public function testCollectorsAreCollectorInstances(): void
    {
        $registry = Registry::build();

        foreach ($registry->collectors() as $class => $instance) {
            $this->assertInstanceOf($class, $instance);
        }
    }

    public function testDetectorsAreDetectorInstances(): void
    {
        $registry = Registry::build();

        foreach ($registry->detectors() as $class => $instance) {
            $this->assertInstanceOf($class, $instance);
        }
    }
}
