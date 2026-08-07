<?php

namespace Scavier\Engine\Contract;
use Scavier\Engine\Context;

interface DetectorInterface
{
    /**
     * @return list<class-string<CollectorInterface|DetectorInterface>> Collectors or detectors this one depends on.
     */
    public static function dependencies(): array;

    /**
     * Analyze context data and return structured findings, or null if nothing detected.
     *
     * @return array<string, mixed>|null
     */
    public function detect(Context $context): ?array;
}