<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

use Closure;
use RuntimeException;

final class CallableRequestSignals implements RequestSignals
{
    private readonly Closure $isAdmin;
    private readonly Closure $isAjax;
    private readonly Closure $isRest;
    private readonly Closure $hasAuthenticatedApplicationPassword;
    private readonly Closure $isRestCookieAuthenticated;
    private readonly Closure $isXmlRpc;
    private readonly Closure $isWpCli;
    private readonly Closure $isCron;
    private readonly Closure $requestUri;
    private readonly Closure $requestParameter;

    public function __construct(
        callable $isAdmin,
        callable $isAjax,
        callable $isRest,
        callable $hasAuthenticatedApplicationPassword,
        callable $isRestCookieAuthenticated,
        callable $isXmlRpc,
        callable $isWpCli,
        callable $isCron,
        callable $requestUri,
        callable $requestParameter,
    ) {
        $this->isAdmin = Closure::fromCallable($isAdmin);
        $this->isAjax = Closure::fromCallable($isAjax);
        $this->isRest = Closure::fromCallable($isRest);
        $this->hasAuthenticatedApplicationPassword = Closure::fromCallable($hasAuthenticatedApplicationPassword);
        $this->isRestCookieAuthenticated = Closure::fromCallable($isRestCookieAuthenticated);
        $this->isXmlRpc = Closure::fromCallable($isXmlRpc);
        $this->isWpCli = Closure::fromCallable($isWpCli);
        $this->isCron = Closure::fromCallable($isCron);
        $this->requestUri = Closure::fromCallable($requestUri);
        $this->requestParameter = Closure::fromCallable($requestParameter);
    }

    /**
     * Build adapters around WordPress functions and globals.
     *
     * Cookie authentication is intentionally supplied by the integration. A
     * current user or arbitrary Cookie header is not enough to identify the
     * REST authentication mechanism safely.
     */
    public static function fromWordPress(callable $isRestCookieAuthenticated): self
    {
        return new self(
            isAdmin: static fn (): bool => function_exists('is_admin') && (bool) \is_admin(),
            isAjax: static fn (): bool => function_exists('wp_doing_ajax')
                ? (bool) \wp_doing_ajax()
                : (defined('DOING_AJAX') && (bool) constant('DOING_AJAX')),
            isRest: static fn (): bool => defined('REST_REQUEST') && (bool) constant('REST_REQUEST'),
            hasAuthenticatedApplicationPassword: static fn (): bool => function_exists('rest_get_authenticated_app_password')
                && \rest_get_authenticated_app_password() !== null,
            isRestCookieAuthenticated: $isRestCookieAuthenticated,
            isXmlRpc: static fn (): bool => defined('XMLRPC_REQUEST') && (bool) constant('XMLRPC_REQUEST'),
            isWpCli: static fn (): bool => defined('WP_CLI') && (bool) constant('WP_CLI'),
            isCron: static fn (): bool => function_exists('wp_doing_cron')
                ? (bool) \wp_doing_cron()
                : (defined('DOING_CRON') && (bool) constant('DOING_CRON')),
            requestUri: static fn (): string => isset($_SERVER['REQUEST_URI']) && is_string($_SERVER['REQUEST_URI'])
                ? $_SERVER['REQUEST_URI']
                : '/',
            requestParameter: static function (string $name): ?string {
                $value = $_REQUEST[$name] ?? null;

                return is_scalar($value) ? (string) $value : null;
            },
        );
    }

    public function isAdmin(): bool
    {
        return (bool) ($this->isAdmin)();
    }

    public function isAjax(): bool
    {
        return (bool) ($this->isAjax)();
    }

    public function isRest(): bool
    {
        return (bool) ($this->isRest)();
    }

    public function hasAuthenticatedApplicationPassword(): bool
    {
        return (bool) ($this->hasAuthenticatedApplicationPassword)();
    }

    public function isRestCookieAuthenticated(): bool
    {
        return (bool) ($this->isRestCookieAuthenticated)();
    }

    public function isXmlRpc(): bool
    {
        return (bool) ($this->isXmlRpc)();
    }

    public function isWpCli(): bool
    {
        return (bool) ($this->isWpCli)();
    }

    public function isCron(): bool
    {
        return (bool) ($this->isCron)();
    }

    public function requestUri(): string
    {
        return (string) ($this->requestUri)();
    }

    public function requestParameter(string $name): ?string
    {
        $value = ($this->requestParameter)($name);

        return $value === null ? null : (string) $value;
    }
}
