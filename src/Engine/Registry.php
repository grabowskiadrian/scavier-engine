<?php

namespace Scavier\Engine;

use Scavier\Engine\Contract\CollectorInterface;
use Scavier\Engine\Contract\DetectorInterface;

/**
 * Auto-discovers and holds all available collectors and detectors
 * by scanning the src/Collector and src/Detector directories.
 */
final class Registry
{
    private const SCAN_DIRS = [
        'Scavier\\Collector\\' => __DIR__ . '/../Collector',
        'Scavier\\Detector\\' => __DIR__ . '/../Detector',
    ];

    /** @var array<class-string<CollectorInterface>, CollectorInterface> */
    private array $collectors = [];

    /** @var array<class-string<DetectorInterface>, DetectorInterface> */
    private array $detectors = [];

    public static function build(): self
    {
        $registry = new self();

        foreach (self::SCAN_DIRS as $namespace => $dir) {
            foreach (self::discoverClasses($namespace, $dir) as $class) {
                if (is_subclass_of($class, CollectorInterface::class)) {
                    $registry->collectors[$class] = new $class();
                }

                if (is_subclass_of($class, DetectorInterface::class)) {
                    $registry->detectors[$class] = new $class();
                }
            }
        }

        return $registry;
    }

    /**
     * @return list<class-string>
     */
    private static function discoverClasses(string $namespace, string $dir): array
    {
        if (!is_dir($dir)) {
            return [];
        }

        $classes = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            $relativePath = substr($file->getPathname(), strlen($dir) + 1);
            $class = $namespace . str_replace(['/', '.php'], ['\\', ''], $relativePath);

            if (class_exists($class)) {
                $classes[] = $class;
            }
        }

        return $classes;
    }

    public function addCollector(CollectorInterface $collector): void
    {
        $this->collectors[$collector::class] = $collector;
    }

    public function addDetector(DetectorInterface $detector): void
    {
        $this->detectors[$detector::class] = $detector;
    }

    public function collectors(): array
    {
        return $this->collectors;
    }

    public function detectors(): array
    {
        return $this->detectors;
    }
}