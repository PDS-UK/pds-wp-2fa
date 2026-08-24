<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

use Closure;

final class AdminInitHook
{
    private readonly Closure $delegate;

    public function __construct(
        private readonly RequestClassifier $classifier,
        private readonly Gate $gate,
        callable $delegate,
    ) {
        $this->delegate = Closure::fromCallable($delegate);
    }

    public function __invoke(): void
    {
        $context = $this->classifier->classify();
        if (!$context->isAdminGateRequest()) {
            return;
        }

        ($this->delegate)($context, $this->gate->decide($context));
    }
}
