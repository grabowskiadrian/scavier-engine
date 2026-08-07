<?php

namespace Scavier\Engine\Contract;

abstract class Collector implements CollectorInterface
{
    public static function dependencies(): array
    {
        return [];
    }
}
