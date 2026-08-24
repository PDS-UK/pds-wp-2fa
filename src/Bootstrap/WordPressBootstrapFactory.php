<?php

declare(strict_types=1);

namespace PDS\WP2FA\Bootstrap;

use PDS\WP2FA\Method\ProviderRegistry;
use PDS\WP2FA\Persistence\MigrationRunner;
use PDS\WP2FA\Persistence\SchemaDefinition;
use PDS\WP2FA\Persistence\TableNames;
use PDS\WP2FA\Persistence\WordPressWpdb;
use PDS\WP2FA\Runtime\RuntimeGate;
use PDS\WP2FA\Runtime\RuntimeResponseEmitter;
use PDS\WP2FA\Runtime\RuntimeState;
use PDS\WP2FA\Runtime\UnavailableIdentityBindingReader;
use PDS\WP2FA\Runtime\WordPressIdentityBindingReader;
use PDS\WP2FA\WordPress\CallableHookRegistrar;
use PDS\WP2FA\WordPress\CallableRequestSignals;
use PDS\WP2FA\WordPress\RequestClassifier;

/** Builds the real WordPress graph while keeping absent dependencies closed. */
final class WordPressBootstrapFactory
{
    /** @param iterable<\PDS\WP2FA\Method\AuthenticationMethodProvider> $providers */
    public function create(string $pluginFile, iterable $providers = []): PluginBootstrap
    {
        $db = null;
        $reader = new UnavailableIdentityBindingReader();
        $migrations = null;

        global $wpdb;
        if (is_object($wpdb)) {
            try {
                $db = new WordPressWpdb($wpdb);
                $tables = new TableNames($db->prefix());
                $reader = new WordPressIdentityBindingReader($db, $tables);
                $migrations = new MigrationRunner(
                    $db,
                    $tables,
                    new SchemaDefinition($tables, $db->get_charset_collate()),
                );
            } catch (\Throwable) {
                $reader = new UnavailableIdentityBindingReader();
                $migrations = null;
            }
        }

        $runtime = RuntimeState::fromWordPress($reader, $migrations);
        $signals = CallableRequestSignals::fromWordPress(
            static fn (): bool => function_exists('is_user_logged_in') && (bool) \is_user_logged_in(),
        );
        $classifier = new RequestClassifier($signals);
        $gate = new RuntimeGate($runtime);
        $registrar = CallableHookRegistrar::fromWordPress();
        $hooks = new RuntimeHookSet(
            $registrar,
            $runtime,
            $classifier,
            $gate,
            new RuntimeResponseEmitter(),
        );
        $registry = (new ProviderRegistryFactory())->build($providers);

        return new PluginBootstrap($pluginFile, $runtime, $hooks, $registry);
    }
}
