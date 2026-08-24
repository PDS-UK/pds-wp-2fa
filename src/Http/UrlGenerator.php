<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

interface UrlGenerator
{
    public function adminPage(string $route, ?string $returnTo = null): string;
    public function adminPost(string $action): string;
    public function login(string $returnTo): string;
}
