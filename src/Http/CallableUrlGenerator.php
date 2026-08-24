<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use Closure;

final class CallableUrlGenerator implements UrlGenerator
{
    private readonly Closure $adminPageCallback;
    private readonly Closure $adminPostCallback;
    private readonly Closure $loginCallback;

    public function __construct(callable $adminPage, callable $adminPost, callable $login)
    {
        $this->adminPageCallback = Closure::fromCallable($adminPage);
        $this->adminPostCallback = Closure::fromCallable($adminPost);
        $this->loginCallback = Closure::fromCallable($login);
    }

    public function adminPage(string $route, ?string $returnTo = null): string
    {
        return (string) ($this->adminPageCallback)($route, $returnTo);
    }

    public function adminPost(string $action): string
    {
        return (string) ($this->adminPostCallback)($action);
    }

    public function login(string $returnTo): string
    {
        return (string) ($this->loginCallback)($returnTo);
    }
}
