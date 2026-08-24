<?php

declare(strict_types=1);

namespace PDS\WP2FA\WordPress;

final class WordPressGateHooks
{
    public const ADMIN_INIT_PRIORITY = 1;
    public const REST_AUTHENTICATION_ERRORS_PRIORITY = 110;

    public function __construct(
        private readonly HookRegistrar $registrar,
        private readonly AdminInitHook $adminInit,
        private readonly RestAuthenticationErrorsHook $restAuthenticationErrors,
    ) {
    }

    public function register(): void
    {
        $this->registrar->addAction(
            'admin_init',
            $this->adminInit,
            self::ADMIN_INIT_PRIORITY,
            0,
        );
        $this->registrar->addFilter(
            'rest_authentication_errors',
            $this->restAuthenticationErrors,
            self::REST_AUTHENTICATION_ERRORS_PRIORITY,
            1,
        );
    }
}
