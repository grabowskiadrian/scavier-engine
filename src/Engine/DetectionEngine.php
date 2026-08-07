<?php

namespace Scavier\Engine;

use Scavier\Engine\Contract\CollectorInterface;

/**
 * Core analysis pipeline: resolves dependencies, runs collectors, then detectors.
 */
final class DetectionEngine
{
    public function __construct(
        private Registry $registry,
        private DependencyResolver $resolver
    ) {
    }

    public function analyze(Target $target, array $requested): array
    {
        $context = new Context();

        $selectedDetectors = [];

        foreach ($requested as $class) {
            if (isset($this->registry->detectors()[$class])) {
                $selectedDetectors[$class] = $this->registry->detectors()[$class];
            }
        }

        // Resolve detector order first (to discover full tree including transitive deps)
        $detectorPipeline = $this->resolver->resolve(
            $this->registry->detectors(),
            array_keys($selectedDetectors)
        );

        // Collect all required collectors from the full detector tree
        $requiredCollectors = [];

        foreach ($detectorPipeline as $detector) {
            $this->collectCollectorDeps($detector::class, $requiredCollectors);
        }

        // Resolve and run collectors
        $collectorPipeline = $this->resolver->resolve(
            $this->registry->collectors(),
            array_unique($requiredCollectors)
        );

        $startTime = microtime(true);

        foreach ($collectorPipeline as $collector) {
            $collector->execute($target, $context);
        }

        // Run detectors in resolved order
        $result = [];
        $detectorsRun = [];
        $tags = [];

        foreach ($detectorPipeline as $detector) {
            $data = $detector->detect($context);

            if ($data === null) {
                continue;
            }

            // Collect tags before merging into result
            if (isset($data['_tags'])) {
                foreach ($data['_tags'] as $tag) {
                    if (!in_array($tag, $tags, true)) {
                        $tags[] = $tag;
                    }
                }
                unset($data['_tags']);
            }

            $context->setDetectorResult($detector::class, $data);
            $detectorsRun[] = $this->shortName($detector::class);

            foreach ($data as $category => $values) {
                if (!isset($result[$category])) {
                    $result[$category] = [];
                }

                if (is_array($values) && is_array($result[$category])) {
                    $result[$category] = $this->deepMerge($result[$category], $values);
                } else {
                    $result[$category] = $values;
                }
            }
        }

        $scanDuration = round(microtime(true) - $startTime, 3);

        sort($tags);

        // Add metadata
        $result['_meta'] = [
            'scan_duration' => $scanDuration,
            'timestamp' => date('c'),
            'engine_version' => Scavier::VERSION,
            'detectors_run' => $detectorsRun,
            'tags' => $tags,
        ];

        return $result;
    }

    /**
     * Deep merge two arrays, preserving string keys and appending numeric keys.
     */
    private function deepMerge(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            if (is_string($key) && isset($base[$key]) && is_array($base[$key]) && is_array($value)) {
                $base[$key] = $this->deepMerge($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }

        return $base;
    }

    private function shortName(string $class): string
    {
        $short = (new \ReflectionClass($class))->getShortName();

        return strtolower(preg_replace('/Detector$/', '', $short));
    }

    private function collectCollectorDeps(string $class, array &$collectors): void
    {
        foreach ($class::dependencies() as $dep) {
            if (is_subclass_of($dep, CollectorInterface::class)) {
                if (!in_array($dep, $collectors, true)) {
                    $collectors[] = $dep;
                    $this->collectCollectorDeps($dep, $collectors);
                }
            }
        }
    }
}
