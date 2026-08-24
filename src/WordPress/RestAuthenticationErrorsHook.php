<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

use Closure;

final class RestAuthenticationErrorsHook
{
    private readonly Closure $delegate;

    public function __construct(
        private readonly RequestClassifier $classifier,
        private readonly Gate $gate,
        callable $delegate,
    ) {
        $this->delegate = Closure::fromCallable($delegate);
    }

    public function __invoke(mixed $existingResult): mixed
    {
        if ($existingResult !== null) {
            return $existingResult;
        }

        $context = $this->classifier->classify();
        if ($context->type() !== RequestType::REST_COOKIE) {
            return null;
        }

        $decision = $this->gate->decide($context);
        if (in_array($decision->outcome(), [GateDecision::ALLOW, GateDecision::BYPASS], true)) {
            return null;
        }

        return ($this->delegate)($context, $decision);
    }
}
