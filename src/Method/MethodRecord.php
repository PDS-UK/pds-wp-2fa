<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

use DateTimeImmutable;

final class MethodRecord
{
    public function __construct(
        private MethodId $methodId,
        private UserId $userId,
        private InstallationBinding $installation,
        private ProviderKey $providerKey,
        private int $schemaVersion,
        private FriendlyLabel $label,
        private MethodStatus $status,
        private DateTimeImmutable $createdAt,
        private DateTimeImmutable $updatedAt,
        private ?DateTimeImmutable $revokedAt,
        private ?UserId $revokedBy,
        private int $revision,
        ?LastUsedAt $lastUsedAt = null,
    ) {
        if ($schemaVersion < 1 || $revision < 1) {
            throw new \InvalidArgumentException('Method versions must be positive.');
        }
        if ($updatedAt < $createdAt) {
            throw new \InvalidArgumentException('Method timestamps cannot move backwards.');
        }
        if ($status === MethodStatus::REVOKED && $revokedAt === null) {
            throw new \InvalidArgumentException('Revoked methods require a revocation timestamp.');
        }

        $this->lastUsedAt = $lastUsedAt ?? LastUsedAt::never();
    }

    private LastUsedAt $lastUsedAt;

    public function methodId(): MethodId { return $this->methodId; }
    public function userId(): UserId { return $this->userId; }
    public function installation(): InstallationBinding { return $this->installation; }
    public function providerKey(): ProviderKey { return $this->providerKey; }
    public function schemaVersion(): int { return $this->schemaVersion; }
    public function label(): FriendlyLabel { return $this->label; }
    public function status(): MethodStatus { return $this->status; }
    public function createdAt(): DateTimeImmutable { return $this->createdAt; }
    public function updatedAt(): DateTimeImmutable { return $this->updatedAt; }
    public function lastUsedAt(): LastUsedAt { return $this->lastUsedAt; }
    public function revokedAt(): ?DateTimeImmutable { return $this->revokedAt; }
    public function revokedBy(): ?UserId { return $this->revokedBy; }
    public function revision(): int { return $this->revision; }

    public function isActive(): bool
    {
        return $this->status === MethodStatus::ACTIVE;
    }
}
