<?php

declare(strict_types=1);

namespace PDS\WP2FA\Identity;

final class ConfigurationResolution
{
    public const CONFIGURED = 'configured';
    public const UNCONFIGURED = 'unconfigured';
    public const CONFIGURATION_ERROR = 'configuration_error';

    private string $status;

    private ?InstallationIdentity $identity;

    private ?string $errorCode;

    private function __construct(string $status, ?InstallationIdentity $identity, ?string $errorCode)
    {
        $this->status = $status;
        $this->identity = $identity;
        $this->errorCode = $errorCode;
    }

    public static function configured(InstallationIdentity $identity): self
    {
        return new self(self::CONFIGURED, $identity, null);
    }

    public static function unconfigured(): self
    {
        return new self(self::UNCONFIGURED, null, 'missing_identity');
    }

    public static function error(string $errorCode): self
    {
        return new self(self::CONFIGURATION_ERROR, null, $errorCode);
    }

    public function status(): string
    {
        return $this->status;
    }

    public function isConfigured(): bool
    {
        return $this->status === self::CONFIGURED;
    }

    public function errorCode(): ?string
    {
        return $this->errorCode;
    }

    /**
     * Return the non-secret fingerprint, never the configured identity.
     *
     * @throws \LogicException when the configuration is not valid.
     */
    public function fingerprint(): IdentityFingerprint
    {
        if (!$this->isConfigured() || $this->identity === null) {
            throw new \LogicException('A fingerprint is unavailable for this configuration state.');
        }

        return $this->identity->fingerprint();
    }

    public function diagnostics(): array
    {
        return [
            'status' => $this->status,
            'error_code' => $this->errorCode,
            'configured_fingerprint' => $this->isConfigured() ? $this->fingerprint()->redacted() : null,
        ];
    }

    public function __debugInfo(): array
    {
        return $this->diagnostics();
    }
}
