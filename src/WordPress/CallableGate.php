<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

use Closure;
use InvalidArgumentException;

final class CallableGate implements Gate
{
    private readonly Closure $callback;

    public function __construct(callable $callback)
    {
        $this->callback = Closure::fromCallable($callback);
    }

    public function decide(RequestContext $context): GateDecision
    {
        $decision = ($this->callback)($context);
        if (!$decision instanceof GateDecision) {
            throw new InvalidArgumentException('The WordPress gate callback must return a GateDecision.');
        }

        return $decision;
    }
}
