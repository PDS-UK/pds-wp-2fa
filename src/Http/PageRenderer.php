<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

interface PageRenderer
{
    /** @param array<string, mixed> $view */
    public function render(string $route, array $view, AuthenticationSnapshot $authentication): string;
}
