<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class InstallationIdentityRuntime
{
    private IdentityConfigurationResolver $configurationResolver;

    private IdentityBindingReader $bindingReader;

    public function __construct(
        IdentityConfigurationResolver $configurationResolver,
        IdentityBindingReader $bindingReader
    ) {
        $this->configurationResolver = $configurationResolver;
        $this->bindingReader = $bindingReader;
    }

    /**
     * Inspect the runtime binding without creating or changing persistence.
     *
     * @param string|EnvironmentType $environment
     */
    public function inspect(ConfigurationSources $sources, $environment): IdentityBindingState
    {
        $environmentType = $environment instanceof EnvironmentType
            ? $environment
            : EnvironmentType::classify($environment);
        $configuration = $this->configurationResolver->resolve($sources);

        if ($configuration->status() === ConfigurationResolution::UNCONFIGURED) {
            return new IdentityBindingState(
                IdentityBindingState::UNCONFIGURED,
                $environmentType,
                $configuration,
                null,
                'missing_identity'
            );
        }

        if ($configuration->status() === ConfigurationResolution::CONFIGURATION_ERROR) {
            return new IdentityBindingState(
                IdentityBindingState::CONFIGURATION_ERROR,
                $environmentType,
                $configuration,
                null,
                $configuration->errorCode() ?? 'invalid_configuration'
            );
        }

        try {
            $binding = $this->bindingReader->read();
        } catch (\Throwable $exception) {
            return new IdentityBindingState(
                IdentityBindingState::CONFIGURATION_ERROR,
                $environmentType,
                $configuration,
                null,
                'binding_unavailable'
            );
        }

        if ($binding === null) {
            return new IdentityBindingState(
                IdentityBindingState::UNINITIALIZED,
                $environmentType,
                $configuration,
                null,
                'missing_binding'
            );
        }

        if (!$binding->identityFingerprint()->equals($configuration->fingerprint())) {
            return new IdentityBindingState(
                IdentityBindingState::IDENTITY_MISMATCH,
                $environmentType,
                $configuration,
                $binding,
                'fingerprint_mismatch'
            );
        }

        if (!$binding->environment()->equals($environmentType)) {
            return new IdentityBindingState(
                IdentityBindingState::IDENTITY_MISMATCH,
                $environmentType,
                $configuration,
                $binding,
                'environment_mismatch'
            );
        }

        return new IdentityBindingState(
            IdentityBindingState::ACTIVE,
            $environmentType,
            $configuration,
            $binding,
            'binding_match'
        );
    }
}
