<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

interface RequestSignals
{
    public function isAdmin(): bool;

    public function isAjax(): bool;

    public function isRest(): bool;

    public function hasAuthenticatedApplicationPassword(): bool;

    public function isRestCookieAuthenticated(): bool;

    public function isXmlRpc(): bool;

    public function isWpCli(): bool;

    public function isCron(): bool;

    public function requestUri(): string;

    public function requestParameter(string $name): ?string;
}
