<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

use Closure;

final class AdminPages
{
    /** @param array<string, callable> $postHandlers */
    public function __construct(
        private readonly AdminPageRegistry $registry,
        callable $settingsPage,
        callable $usersPage,
        callable $auditPage,
        private readonly array $postHandlers = [],
    ) {
        $this->settingsPage = Closure::fromCallable($settingsPage);
        $this->usersPage = Closure::fromCallable($usersPage);
        $this->auditPage = Closure::fromCallable($auditPage);
        foreach ($postHandlers as $handler) {
            if (!is_callable($handler)) {
                throw new \InvalidArgumentException('Admin post handlers must be callable.');
            }
        }
    }

    private readonly Closure $settingsPage;
    private readonly Closure $usersPage;
    private readonly Closure $auditPage;

    public function register(): void
    {
        $this->registry->addMenuPage('pds-wp-2fa-settings', Capability::MANAGE, $this->settingsPage);
        $this->registry->addMenuPage('pds-wp-2fa-users', Capability::VIEW_STATUS, $this->usersPage);
        $this->registry->addMenuPage('pds-wp-2fa-audit', Capability::VIEW_AUDIT, $this->auditPage);
        foreach ($this->postHandlers as $action => $handler) {
            $this->registry->addPostAction($action, $handler);
        }
    }
}
