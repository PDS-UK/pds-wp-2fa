<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use PDS\WP2FA\WordPress\SafeRedirectTarget;

final class LoginRedirector
{
    public function __construct(
        private readonly SafeRedirectTarget $targets,
        private readonly UrlGenerator $urls,
    ) {
    }

    public function redirect(string $candidate, AuthenticationSnapshot $snapshot): string
    {
        $target = $this->targets->validate($candidate);
        if (!$snapshot->identityAvailable() || !$snapshot->protected() || !$snapshot->isPending()) {
            return $target;
        }

        if ($snapshot->policyMode() === AuthenticationSnapshot::MODE_GRACE) {
            return $target;
        }

        return $this->urls->adminPage(RouteGate::requiredRoute($snapshot), $target);
    }
}
