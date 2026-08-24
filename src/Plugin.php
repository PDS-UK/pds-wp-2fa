<?php

declare(strict_types=1);

namespace PDS\WP2FA;

use PDS\WP2FA\Bootstrap\PluginBootstrap;
use PDS\WP2FA\Bootstrap\WordPressBootstrapFactory;

/** Public plugin entry point used by the WordPress loader. */
final class Plugin
{
    private static ?PluginBootstrap $bootstrap = null;

    public static function boot(?PluginBootstrap $bootstrap = null): PluginBootstrap
    {
        if (self::$bootstrap !== null) {
            return self::$bootstrap;
        }

        $bootstrap ??= (new WordPressBootstrapFactory())->create(
            defined('PDS_WP_2FA_PLUGIN_FILE')
                ? (string) constant('PDS_WP_2FA_PLUGIN_FILE')
                : dirname(__DIR__) . '/pds-wp-2fa.php',
        );

        // Registration exceptions are intentionally allowed to surface. A
        // plugin that cannot install its gate must not continue as if 2FA were
        // active while leaving protected requests unguarded.
        self::$bootstrap = $bootstrap->register();

        return self::$bootstrap;
    }

    public static function activate(): void
    {
        self::bootstrapForLifecycle()->activate();
    }

    public static function deactivate(): void
    {
        self::bootstrapForLifecycle()->deactivate();
    }

    public static function uninstall(): void
    {
        self::bootstrapForLifecycle()->uninstall();
    }

    public static function runtime(): PluginBootstrap
    {
        return self::boot();
    }

    /** Test-only reset seam; it has no effect in a normal request lifecycle. */
    public static function resetForTests(): void
    {
        self::$bootstrap = null;
    }

    private static function bootstrapForLifecycle(): PluginBootstrap
    {
        return self::$bootstrap ?? self::boot();
    }
}
