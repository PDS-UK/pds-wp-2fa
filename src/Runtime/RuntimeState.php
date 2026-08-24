<?php

declare(strict_types=1);

namespace PDS\WP2FA\Runtime;

use PDS\WP2FA\Identity\ConfigurationSources;
use PDS\WP2FA\Identity\EnvironmentType;
use PDS\WP2FA\Identity\IdentityBindingReader;
use PDS\WP2FA\Identity\IdentityConfigurationResolver;
use PDS\WP2FA\Identity\IdentityBindingState;
use PDS\WP2FA\Identity\InstallationIdentityRuntime;
use PDS\WP2FA\Persistence\MigrationRunner;

/** Re-evaluates deployment identity and persistence readiness without writes. */
final class RuntimeState
{
    private ?RuntimeStatus $status = null;

    public function __construct(
        private readonly InstallationIdentityRuntime $identity,
        private readonly IdentityBindingReader $bindingReader,
        private readonly ?MigrationRunner $migrations,
        private readonly string $environment,
    ) {
    }

    public static function fromWordPress(
        IdentityBindingReader $bindingReader,
        ?MigrationRunner $migrations,
        ?string $environment = null,
    ): self {
        return new self(
            new InstallationIdentityRuntime(new IdentityConfigurationResolver(), $bindingReader),
            $bindingReader,
            $migrations,
            $environment ?? self::wordpressEnvironment(),
        );
    }

    public function refresh(): RuntimeStatus
    {
        $identity = $this->identity->inspect(
            ConfigurationSources::fromRuntime(),
            EnvironmentType::classify($this->environment),
        );

        $schemaReady = false;
        $reason = 'persistence_unavailable';
        if ($this->migrations !== null) {
            try {
                $schemaReady = $this->migrations->isReady();
                $reason = $schemaReady ? 'ready' : 'schema_not_ready';
            } catch (\Throwable) {
                $reason = 'schema_unavailable';
            }
        }

        $this->status = new RuntimeStatus(
            $identity,
            $this->migrations !== null,
            $schemaReady,
            true,
            $reason,
        );

        return $this->status;
    }

    public function status(): RuntimeStatus
    {
        return $this->status ?? $this->refresh();
    }

    public function identityState(): IdentityBindingState
    {
        return $this->status()->identity();
    }

    public function migrations(): ?MigrationRunner
    {
        return $this->migrations;
    }

    public function bindingReader(): IdentityBindingReader
    {
        return $this->bindingReader;
    }

    public function environment(): string
    {
        return $this->environment;
    }

    private static function wordpressEnvironment(): string
    {
        if (function_exists('wp_get_environment_type')) {
            $value = \wp_get_environment_type();

            return is_string($value) ? $value : EnvironmentType::PRODUCTION;
        }

        return EnvironmentType::PRODUCTION;
    }
}
