<?php

namespace Scavier\Engine\Contract;

abstract class Detector implements DetectorInterface
{
    public static function dependencies(): array
    {
        return [];
    }
}
