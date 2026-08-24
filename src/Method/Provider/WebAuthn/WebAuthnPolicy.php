<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

final class WebAuthnPolicy
{
    /** @var list<int> */
    private array $algorithms;

    /** @var list<string> */
    private array $allowedOrigins;

    /**
     * The MVP deliberately uses one exact origin and requires UV and a
     * discoverable credential. Subdomain and alternate-origin matching are
     * not enabled by this policy object.
     *
     * @param list<string> $allowedOrigins
     * @param list<int> $algorithms
     */
    public function __construct(
        private string $rpId,
        array $allowedOrigins,
        private string $relyingPartyName = 'PDS WP 2FA',
        private bool $enabled = true,
        private int $timeoutMilliseconds = 60000,
        array $algorithms = [-7, -257],
        private bool $requireUserVerification = true,
        private bool $requireDiscoverableCredentials = true,
    ) {
        $this->rpId = self::normalizeRpId($rpId);
        if ($relyingPartyName === '' || strlen($relyingPartyName) > 128) {
            throw new \InvalidArgumentException('The relying-party name is invalid.');
        }
        if ($timeoutMilliseconds < 1000 || $timeoutMilliseconds > 300000) {
            throw new \InvalidArgumentException('The WebAuthn timeout is outside the supported range.');
        }
        if (!$requireUserVerification) {
            throw new \InvalidArgumentException('WebAuthn user verification is required.');
        }
        if (!$requireDiscoverableCredentials) {
            throw new \InvalidArgumentException('WebAuthn discoverable credentials are required.');
        }
        if ($algorithms === []) {
            throw new \InvalidArgumentException('At least one WebAuthn algorithm is required.');
        }
        foreach ($algorithms as $algorithm) {
            if (!is_int($algorithm) || !in_array($algorithm, [-7, -257], true)) {
                throw new \InvalidArgumentException('The WebAuthn algorithm is not allow-listed.');
            }
        }
        $this->algorithms = array_values(array_unique($algorithms));

        $normalizedOrigins = [];
        foreach ($allowedOrigins as $origin) {
            $normalized = self::normalizeOrigin($origin);
            $parsed = parse_url($normalized);
            if (!is_array($parsed) || ($parsed['host'] ?? '') !== $this->rpId) {
                throw new \InvalidArgumentException('WebAuthn origins must match the configured RP ID exactly.');
            }
            $normalizedOrigins[] = $normalized;
        }
        if ($normalizedOrigins === []) {
            throw new \InvalidArgumentException('At least one WebAuthn origin is required.');
        }
        $this->allowedOrigins = array_values(array_unique($normalizedOrigins));
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function assertEnabled(): void
    {
        if (!$this->enabled) {
            throw WebAuthnException::unavailable();
        }
    }

    public function rpId(): string
    {
        return $this->rpId;
    }

    /** @return list<string> */
    public function allowedOrigins(): array
    {
        return $this->allowedOrigins;
    }

    public function relyingPartyName(): string
    {
        return $this->relyingPartyName;
    }

    public function timeoutMilliseconds(): int
    {
        return $this->timeoutMilliseconds;
    }

    /** @return list<int> */
    public function algorithms(): array
    {
        return $this->algorithms;
    }

    public function userVerificationRequirement(): string
    {
        return AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED;
    }

    public function residentKeyRequirement(): string
    {
        return AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED;
    }

    public function attestationConveyance(): string
    {
        return PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    }

    public function isAllowedOrigin(string $origin): bool
    {
        try {
            return in_array(self::normalizeOrigin($origin), $this->allowedOrigins, true);
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    private static function normalizeRpId(string $rpId): string
    {
        $rpId = strtolower(trim($rpId));
        if ($rpId === '' || strlen($rpId) > 253 || str_contains($rpId, '://') || str_contains($rpId, ':')) {
            throw new \InvalidArgumentException('The WebAuthn RP ID is invalid.');
        }
        if ($rpId === 'localhost') {
            return $rpId;
        }
        if (filter_var($rpId, FILTER_VALIDATE_IP) !== false) {
            throw new \InvalidArgumentException('IP addresses are not valid WebAuthn RP IDs.');
        }
        $labels = explode('.', $rpId);
        foreach ($labels as $label) {
            if ($label === '' || strlen($label) > 63 || preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/', $label) !== 1) {
                throw new \InvalidArgumentException('The WebAuthn RP ID is invalid.');
            }
        }

        return $rpId;
    }

    private static function normalizeOrigin(string $origin): string
    {
        $origin = trim($origin);
        $parsed = parse_url($origin);
        if (!is_array($parsed) || !isset($parsed['scheme'], $parsed['host'])
            || isset($parsed['user'], $parsed['pass'], $parsed['path'], $parsed['query'], $parsed['fragment'])) {
            throw new \InvalidArgumentException('The WebAuthn origin is invalid.');
        }
        $scheme = strtolower((string) $parsed['scheme']);
        $host = strtolower((string) $parsed['host']);
        $port = $parsed['port'] ?? null;
        if ($scheme !== 'https' && !($scheme === 'http' && $host === 'localhost')) {
            throw new \InvalidArgumentException('WebAuthn origins must use HTTPS.');
        }
        if ($port !== null && (!is_int($port) || $port < 1 || $port > 65535)) {
            throw new \InvalidArgumentException('The WebAuthn origin port is invalid.');
        }
        if (($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80)) {
            $port = null;
        }

        return $scheme . '://' . $host . ($port === null ? '' : ':' . $port);
    }
}
