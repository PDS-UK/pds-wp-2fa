<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class IdentityBindingState
{
    public const UNCONFIGURED = 'unconfigured';
    public const UNINITIALIZED = 'uninitialized';
    public const ACTIVE = 'active';
    public const CONFIGURATION_ERROR = 'configuration_error';
    public const IDENTITY_MISMATCH = 'identity_mismatch';

    public const UNAVAILABLE_ERROR_CODE = 'pds_wp_2fa_unavailable';

    private string $status;

    private EnvironmentType $environment;

    private ConfigurationResolution $configuration;

    private ?InstallationBinding $binding;

    private string $reason;

    public function __construct(
        string $status,
        EnvironmentType $environment,
        ConfigurationResolution $configuration,
        ?InstallationBinding $binding,
        string $reason
    ) {
        $this->status = $status;
        $this->environment = $environment;
        $this->configuration = $configuration;
        $this->binding = $binding;
        $this->reason = $reason;
    }

    public function status(): string
    {
        return $this->status;
    }

    public function isActive(): bool
    {
        return $this->status === self::ACTIVE;
    }

    public function allowsSecurityState(): bool
    {
        return $this->isActive();
    }

    public function publicErrorCode(): ?string
    {
        return $this->isActive() ? null : self::UNAVAILABLE_ERROR_CODE;
    }

    public function httpStatus(): int
    {
        return $this->isActive() ? 200 : 503;
    }

    public function reason(): string
    {
        return $this->reason;
    }

    public function environment(): EnvironmentType
    {
        return $this->environment;
    }

    public function binding(): ?InstallationBinding
    {
        return $this->binding;
    }

    public function epoch(): ?int
    {
        return $this->binding?->epoch();
    }

    public function securityScope(): IdentityBindingScope
    {
        if (!$this->isActive() || $this->binding === null) {
            throw new \LogicException('Security scope is unavailable until the identity binding is active.');
        }

        return new IdentityBindingScope($this->binding->identityFingerprint(), $this->binding->epoch());
    }

    /**
     * Redacted operator/status representation. It contains no raw identity or
     * credential material and is safe for a status response boundary.
     *
     * @return array<string, mixed>
     */
    public function diagnostics(): array
    {
        return [
            'status' => $this->status,
            'error_code' => $this->publicErrorCode(),
            'reason' => $this->reason,
            'environment_type' => $this->environment->value(),
            'configured_fingerprint' => $this->configuration->isConfigured()
                ? $this->configuration->fingerprint()->redacted()
                : null,
            'binding_fingerprint' => $this->binding?->identityFingerprint()->redacted(),
            'binding_environment_type' => $this->binding?->environment()->value(),
            'identity_epoch' => $this->binding?->epoch(),
            'security_state_available' => $this->allowsSecurityState(),
        ];
    }

    public function __debugInfo(): array
    {
        return $this->diagnostics();
    }
}
