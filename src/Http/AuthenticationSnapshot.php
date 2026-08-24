<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

use DateTimeImmutable;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\PolicySnapshot;
use PDS\WP2FA\Method\SessionDigest;
use PDS\WP2FA\Method\SessionState;
use PDS\WP2FA\Method\UserId;

final class AuthenticationSnapshot
{
    public const MODE_NOT_REQUIRED = 'not_required';
    public const MODE_CHALLENGE = 'challenge';
    public const MODE_GRACE = 'grace';
    public const MODE_ENROLLMENT_REQUIRED = 'enrollment_required';

    public function __construct(
        private readonly ?UserId $userId,
        private readonly ?SessionDigest $session,
        private readonly ?InstallationBinding $installation,
        private readonly SessionState $state,
        private readonly string $policyMode,
        private readonly bool $cookieAuthenticated = true,
        private readonly bool $protected = true,
        private readonly bool $identityAvailable = true,
        private readonly bool $hasActiveMethod = false,
        private readonly bool $hasRecoveryCodes = false,
        private readonly ?DateTimeImmutable $deadline = null,
        private readonly ?PolicySnapshot $policy = null,
    ) {
        if (!in_array($policyMode, [
            self::MODE_NOT_REQUIRED,
            self::MODE_CHALLENGE,
            self::MODE_GRACE,
            self::MODE_ENROLLMENT_REQUIRED,
        ], true)) {
            throw new \InvalidArgumentException('Unknown two-factor policy mode.');
        }

        if ($identityAvailable && $cookieAuthenticated && ($userId === null || $session === null)) {
            throw new \InvalidArgumentException('Authenticated snapshots require a user and session binding.');
        }
    }

    public static function anonymous(): self
    {
        return new self(null, null, null, SessionState::INVALIDATED, self::MODE_NOT_REQUIRED, false, false);
    }

    public static function unavailable(bool $cookieAuthenticated = true): self
    {
        return new self(null, null, null, SessionState::INVALIDATED, self::MODE_NOT_REQUIRED, $cookieAuthenticated, true, false);
    }

    public function userId(): ?UserId { return $this->userId; }
    public function session(): ?SessionDigest { return $this->session; }
    public function installation(): ?InstallationBinding { return $this->installation; }
    public function state(): SessionState { return $this->state; }
    public function policyMode(): string { return $this->policyMode; }
    public function cookieAuthenticated(): bool { return $this->cookieAuthenticated; }
    public function protected(): bool { return $this->protected; }
    public function identityAvailable(): bool { return $this->identityAvailable; }
    public function hasActiveMethod(): bool { return $this->hasActiveMethod; }
    public function hasRecoveryCodes(): bool { return $this->hasRecoveryCodes; }
    public function deadline(): ?DateTimeImmutable { return $this->deadline; }
    public function policy(): PolicySnapshot { return $this->policy ?? PolicySnapshot::fromArray([]); }

    public function isAuthenticated(): bool
    {
        return $this->cookieAuthenticated && $this->userId !== null && $this->session !== null;
    }

    public function isPending(): bool { return $this->state === SessionState::PENDING; }
    public function isSatisfied(): bool { return $this->state === SessionState::SATISFIED; }
}
