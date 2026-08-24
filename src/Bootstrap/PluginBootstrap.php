<?php

declare(strict_types=1);

namespace PDS\WP2FA\Bootstrap;

use PDS\WP2FA\Method\ProviderRegistry;
use PDS\WP2FA\Runtime\RuntimeState;
use RuntimeException;

/** The idempotent, dependency-composed plugin runtime. */
final class PluginBootstrap
{
    private bool $registered = false;

    public function __construct(
        private readonly string $pluginFile,
        private readonly RuntimeState $runtime,
        private readonly RuntimeHookSet $hooks,
        private readonly ProviderRegistry $providers,
    ) {
    }

    public function register(): self
    {
        if ($this->registered) {
            return $this;
        }

        $this->hooks->register();
        $this->registerLifecycleHooks();
        $this->registered = true;

        return $this;
    }

    public function isRegistered(): bool
    {
        return $this->registered && $this->hooks->isRegistered();
    }

    public function runtime(): RuntimeState
    {
        return $this->runtime;
    }

    public function providers(): ProviderRegistry
    {
        return $this->providers;
    }

    public function activate(): void
    {
        $migrations = $this->runtime->migrations();
        if ($migrations === null) {
            throw new RuntimeException('PDS WP 2FA cannot activate without the WordPress database.');
        }

        // Activation prepares schema only. Identity binding is an explicit
        // operator operation and is never silently created here.
        $migrations->migrate();
        $this->runtime->refresh();
    }

    public function deactivate(): void
    {
        if (function_exists('wp_clear_scheduled_hook')) {
            \wp_clear_scheduled_hook('pds_wp_2fa_audit_prune');
        }
    }

    public function uninstall(): void
    {
        // Uninstall is intentionally non-destructive by default. A future
        // data-retention/deletion command must provide its own explicit,
        // operator-confirmed path rather than deleting security history here.
        if (!defined('PDS_WP_2FA_UNINSTALL_CONFIRM') || constant('PDS_WP_2FA_UNINSTALL_CONFIRM') !== true) {
            return;
        }
    }

    private function registerLifecycleHooks(): void
    {
        if (function_exists('register_activation_hook')) {
            \register_activation_hook($this->pluginFile, ['PDS\\WP2FA\\Plugin', 'activate']);
        }
        if (function_exists('register_deactivation_hook')) {
            \register_deactivation_hook($this->pluginFile, ['PDS\\WP2FA\\Plugin', 'deactivate']);
        }
        if (function_exists('register_uninstall_hook')) {
            \register_uninstall_hook($this->pluginFile, ['PDS\\WP2FA\\Plugin', 'uninstall']);
        }
    }
}
