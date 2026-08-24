<?php

declare(strict_types=1);

namespace PDS\WP2FA\Bootstrap;

use PDS\WP2FA\Http\Route;
use PDS\WP2FA\Runtime\RuntimeResponseEmitter;
use PDS\WP2FA\Runtime\RuntimeState;
use PDS\WP2FA\WordPress\AdminInitHook;
use PDS\WP2FA\WordPress\Gate;
use PDS\WP2FA\WordPress\HookRegistrar;
use PDS\WP2FA\WordPress\RequestClassifier;
use PDS\WP2FA\WordPress\RestAuthenticationErrorsHook;
use PDS\WP2FA\WordPress\WordPressGateHooks;

/** Registers every WordPress boundary owned by the runtime composition. */
final class RuntimeHookSet
{
    private bool $registered = false;

    public function __construct(
        private readonly HookRegistrar $registrar,
        private readonly RuntimeState $runtime,
        private readonly RequestClassifier $classifier,
        private readonly Gate $gate,
        private readonly RuntimeResponseEmitter $responses,
        private readonly ?object $cliCommand = null,
    ) {
    }

    public function register(): void
    {
        if ($this->registered) {
            return;
        }

        $gateHooks = new WordPressGateHooks(
            $this->registrar,
            new AdminInitHook(
                $this->classifier,
                $this->gate,
                fn ($context, $decision): mixed => $this->responses->admin($context, $decision),
            ),
            new RestAuthenticationErrorsHook(
                $this->classifier,
                $this->gate,
                fn ($context, $decision): mixed => $this->responses->restError($context, $decision),
            ),
        );
        $gateHooks->register();

        $this->registrar->addAction('init', [$this, 'onInit'], 1, 0);
        $this->registrar->addAction('wp_login', [$this, 'onLogin'], 10, 2);
        $this->registrar->addAction('clear_auth_cookie', [$this, 'onLogout'], 10, 0);
        $this->registrar->addAction('user_register', [$this, 'onUserMutation'], 10, 1);
        $this->registrar->addAction('profile_update', [$this, 'onUserMutation'], 10, 1);
        $this->registrar->addAction('set_user_role', [$this, 'onUserMutation'], 10, 3);

        // These callbacks deliberately remain fail-closed until the concrete
        // HTTP/admin/console adapters are installed by their owning tickets.
        foreach (Route::actions() as $action) {
            $this->registrar->addAction('admin_post_' . $action, [$this, 'onUnavailableAction'], 1, 0);
        }
        $this->registrar->addAction('rest_api_init', [$this, 'onRestApiInit'], 10, 0);
        $this->registrar->addAction('admin_menu', [$this, 'onAdminMenu'], 20, 0);
        $this->registrar->addAction('wp_cli_init', [$this, 'onWpCliInit'], 10, 0);

        $this->registered = true;
    }

    public function isRegistered(): bool
    {
        return $this->registered;
    }

    public function onInit(): void
    {
        $this->runtime->refresh();
    }

    public function onLogin(string $userLogin = '', mixed $user = null): void
    {
        // Login state is deliberately not written until the persistence and
        // method/session adapters are available. Refreshing here means a
        // repaired installation becomes visible on the next request.
        $this->runtime->refresh();
    }

    public function onLogout(): void
    {
        $this->runtime->refresh();
    }

    public function onUserMutation(int $userId = 0, mixed ...$unused): void
    {
        $this->runtime->refresh();
    }

    public function onUnavailableAction(): void
    {
        $context = $this->classifier->classify();
        $this->responses->admin($context, $this->gate->decide($context));
    }

    public function onRestApiInit(): void
    {
        // The route controller owns REST route definitions. Keeping the hook
        // registered here makes the composition idempotent and gives missing
        // route dependencies no opportunity to turn into a bypass.
    }

    public function onAdminMenu(): void
    {
        // Admin pages are registered by the administration slice once its
        // repositories and authorization seams are available.
    }

    public function onWpCliInit(): void
    {
        if (!defined('WP_CLI') || !(bool) constant('WP_CLI') || $this->cliCommand === null) {
            return;
        }

        if (is_callable(['WP_CLI', 'add_command'])) {
            \WP_CLI::add_command('pds-wp-2fa', $this->cliCommand);
        }
    }
}
