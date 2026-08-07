<?php

namespace Scavier\Engine;

use InvalidArgumentException;
use RuntimeException;

/**
 * Main entry point. Builds the engine and exposes the analyze API.
 */
final class Scavier
{
    public const VERSION = '0.2.0';

    private static ?string $userAgent = null;

    public static function userAgent(): string
    {
        return self::$userAgent ?? 'ScavierEngine/' . self::VERSION;
    }

    public static function setUserAgent(string $ua): void
    {
        self::$userAgent = $ua;
    }

    private Registry $registry;

    private DetectionEngine $engine;

    /** @var array<string, class-string<Contract\Detector>>|null */
    private ?array $detectorMap = null;

    public function __construct()
    {
        $this->registry = Registry::build();

        $this->engine = new DetectionEngine(
            $this->registry,
            new DependencyResolver()
        );
    }

    /**
     * @param array<class-string<Contract\Detector>> $detectors Empty = all detectors
     * @return array{success: bool, data: array|null, error: string|null}
     */
    public function analyze(string $url, array $detectors = []): array
    {
        if (empty($detectors)) {
            $detectors = array_keys($this->registry->detectors());
        }

        try {
            $data = $this->engine->analyze(
                new Target($url),
                $detectors
            );

            return [
                'success' => true,
                'data' => $data,
                'error' => null,
            ];
        } catch (InvalidArgumentException $e) {
            return [
                'success' => false,
                'data' => null,
                'error' => $e->getMessage(),
            ];
        } catch (RuntimeException $e) {
            return [
                'success' => false,
                'data' => null,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * @return array<string, class-string<Contract\Detector>> Short name => FQCN
     */
    public function availableDetectors(): array
    {
        if ($this->detectorMap !== null) {
            return $this->detectorMap;
        }

        $this->detectorMap = [];

        foreach ($this->registry->detectors() as $class => $instance) {
            $short = preg_replace('/Detector$/', '', (new \ReflectionClass($class))->getShortName());
            $this->detectorMap[strtolower($short)] = $class;
        }

        return $this->detectorMap;
    }
}
