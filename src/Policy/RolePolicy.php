<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class RolePolicy
{
    /** @var RoleKey */
    private $roleKey;

    /** @var string */
    private $currentRoleLabel;

    /** @var RolePolicyStatus */
    private $status;

    /** @var bool */
    private $enabledConfiguration;

    /** @var int */
    private $gracePeriodSeconds;

    /** @var DateTimeImmutable|null */
    private $activatedAt;

    /** @var DateTimeImmutable */
    private $discoveredAt;

    /** @var DateTimeImmutable|null */
    private $lastSeenAt;

    /** @var DateTimeImmutable */
    private $createdAt;

    /** @var DateTimeImmutable */
    private $updatedAt;

    public static function discovered(RoleKey $roleKey, string $label, DateTimeImmutable $observedAt, int $gracePeriodSeconds = 0): self
    {
        $observedAt = Time::utc($observedAt);

        return new self(
            $roleKey,
            $label,
            new RolePolicyStatus(RolePolicyStatus::DISABLED),
            false,
            $gracePeriodSeconds,
            null,
            $observedAt,
            $observedAt,
            $observedAt,
            $observedAt,
        );
    }

    public static function fromStorage(
        RoleKey $roleKey,
        string $label,
        RolePolicyStatus $status,
        bool $enabledConfiguration,
        int $gracePeriodSeconds,
        ?DateTimeImmutable $activatedAt,
        DateTimeImmutable $discoveredAt,
        ?DateTimeImmutable $lastSeenAt,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $updatedAt
    ): self {
        return new self(
            $roleKey,
            $label,
            $status,
            $enabledConfiguration,
            $gracePeriodSeconds,
            $activatedAt,
            $discoveredAt,
            $lastSeenAt,
            $createdAt,
            $updatedAt,
        );
    }

    private function __construct(
        RoleKey $roleKey,
        string $currentRoleLabel,
        RolePolicyStatus $status,
        bool $enabledConfiguration,
        int $gracePeriodSeconds,
        ?DateTimeImmutable $activatedAt,
        DateTimeImmutable $discoveredAt,
        ?DateTimeImmutable $lastSeenAt,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $updatedAt
    ) {
        if ($gracePeriodSeconds < 0) {
            throw new \InvalidArgumentException('A grace period cannot be negative.');
        }

        if ($status->isActive() && (!$enabledConfiguration || $activatedAt === null)) {
            throw new \InvalidArgumentException('An active role policy must be enabled and activated.');
        }

        if ($status->isDisabled() && $enabledConfiguration) {
            throw new \InvalidArgumentException('A disabled role policy cannot be enabled.');
        }

        if ($enabledConfiguration && $activatedAt === null) {
            throw new \InvalidArgumentException('An enabled role policy must have an activation anchor.');
        }

        $this->roleKey = $roleKey;
        $this->currentRoleLabel = $currentRoleLabel;
        $this->status = $status;
        $this->enabledConfiguration = $enabledConfiguration;
        $this->gracePeriodSeconds = $gracePeriodSeconds;
        $this->activatedAt = $activatedAt === null ? null : Time::utc($activatedAt);
        $this->discoveredAt = Time::utc($discoveredAt);
        $this->lastSeenAt = $lastSeenAt === null ? null : Time::utc($lastSeenAt);
        $this->createdAt = Time::utc($createdAt);
        $this->updatedAt = Time::utc($updatedAt);
    }

    public function roleKey(): RoleKey
    {
        return $this->roleKey;
    }

    public function currentRoleLabel(): string
    {
        return $this->currentRoleLabel;
    }

    public function status(): RolePolicyStatus
    {
        return $this->status;
    }

    public function enabledConfiguration(): bool
    {
        return $this->enabledConfiguration;
    }

    public function gracePeriodSeconds(): int
    {
        return $this->gracePeriodSeconds;
    }

    public function activatedAt(): ?DateTimeImmutable
    {
        return $this->activatedAt;
    }

    public function discoveredAt(): DateTimeImmutable
    {
        return $this->discoveredAt;
    }

    public function lastSeenAt(): ?DateTimeImmutable
    {
        return $this->lastSeenAt;
    }

    public function createdAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function updatedAt(): DateTimeImmutable
    {
        return $this->updatedAt;
    }

    public function isActive(): bool
    {
        return $this->status->isActive() && $this->enabledConfiguration;
    }

    public function enable(DateTimeImmutable $at): self
    {
        if ($this->enabledConfiguration) {
            return $this;
        }

        $at = Time::utc($at);
        $activatedAt = $this->activatedAt === null ? $at : $this->activatedAt;
        $status = $this->status->isOrphaned()
            ? new RolePolicyStatus(RolePolicyStatus::ORPHANED)
            : new RolePolicyStatus(RolePolicyStatus::ACTIVE);

        return $this->copy(
            $status,
            true,
            $this->gracePeriodSeconds,
            $activatedAt,
            $this->lastSeenAt,
            $this->currentRoleLabel,
            $at,
        );
    }

    public function disable(DateTimeImmutable $at): self
    {
        if (!$this->enabledConfiguration) {
            return $this;
        }

        $status = $this->status->isOrphaned()
            ? new RolePolicyStatus(RolePolicyStatus::ORPHANED)
            : new RolePolicyStatus(RolePolicyStatus::DISABLED);

        return $this->copy(
            $status,
            false,
            $this->gracePeriodSeconds,
            $this->activatedAt,
            $this->lastSeenAt,
            $this->currentRoleLabel,
            Time::utc($at),
        );
    }

    public function reconcileSeen(string $label, DateTimeImmutable $observedAt): self
    {
        $status = $this->enabledConfiguration
            ? new RolePolicyStatus(RolePolicyStatus::ACTIVE)
            : new RolePolicyStatus(RolePolicyStatus::DISABLED);

        return $this->copy(
            $status,
            $this->enabledConfiguration,
            $this->gracePeriodSeconds,
            $this->activatedAt,
            Time::utc($observedAt),
            $label,
            Time::utc($observedAt),
        );
    }

    public function markOrphaned(DateTimeImmutable $observedAt): self
    {
        if ($this->status->isOrphaned()) {
            return $this;
        }

        return $this->copy(
            new RolePolicyStatus(RolePolicyStatus::ORPHANED),
            $this->enabledConfiguration,
            $this->gracePeriodSeconds,
            $this->activatedAt,
            $this->lastSeenAt,
            $this->currentRoleLabel,
            Time::utc($observedAt),
        );
    }

    public function withGracePeriodSeconds(int $gracePeriodSeconds, DateTimeImmutable $at): self
    {
        if ($gracePeriodSeconds < 0) {
            throw new \InvalidArgumentException('A grace period cannot be negative.');
        }

        if ($gracePeriodSeconds === $this->gracePeriodSeconds) {
            return $this;
        }

        return $this->copy(
            $this->status,
            $this->enabledConfiguration,
            $gracePeriodSeconds,
            $this->activatedAt,
            $this->lastSeenAt,
            $this->currentRoleLabel,
            Time::utc($at),
        );
    }

    private function copy(
        RolePolicyStatus $status,
        bool $enabledConfiguration,
        int $gracePeriodSeconds,
        ?DateTimeImmutable $activatedAt,
        ?DateTimeImmutable $lastSeenAt,
        string $currentRoleLabel,
        DateTimeImmutable $updatedAt
    ): self {
        return new self(
            $this->roleKey,
            $currentRoleLabel,
            $status,
            $enabledConfiguration,
            $gracePeriodSeconds,
            $activatedAt,
            $this->discoveredAt,
            $lastSeenAt,
            $this->createdAt,
            $updatedAt,
        );
    }
}
