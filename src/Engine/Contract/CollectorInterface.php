<?php

namespace Scavier\Engine\Contract;

use Scavier\Engine\Context;
use Scavier\Engine\Target;

interface CollectorInterface
{
    /**
     * @return list<class-string<CollectorInterface>> Other collectors this one depends on.
     */
    public static function dependencies(): array;

    /**
     * Fetch raw data and store it in the context.
     */
    public function execute(Target $target, Context $context): void;
}