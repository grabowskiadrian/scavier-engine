<?php

namespace Scavier\Engine;

/**
 * Shared data store passed through the analysis pipeline.
 * Collectors write data objects, detectors read them.
 */
final class Context
{
    /** @var array<class-string, object> */
    private array $data = [];

    /** @var array<class-string, array> */
    private array $results = [];

    public function set(object $object): void
    {
        $this->data[$object::class] = $object;
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T|null
     */
    public function get(string $class): ?object
    {
        return $this->data[$class] ?? null;
    }

    public function has(string $class): bool
    {
        return isset($this->data[$class]);
    }

    /**
     * @return array<class-string, object>
     */
    public function all(): array
    {
        return $this->data;
    }

    public function setDetectorResult(string $detectorClass, array $result): void
    {
        $this->results[$detectorClass] = $result;
    }

    public function getDetectorResult(string $detectorClass): ?array
    {
        return $this->results[$detectorClass] ?? null;
    }

    public function hasDetectorResult(string $detectorClass): bool
    {
        return isset($this->results[$detectorClass]);
    }
}
