<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

final class MethodSnapshot
{
    public function __construct(
        private MethodId $methodId,
        private UserId $userId,
        private InstallationBinding $installation,
        private ProviderKey $providerKey,
        private MethodStatus $status,
        private int $revision,
    ) {
        if ($revision < 1) {
            throw new \InvalidArgumentException('Method snapshot revisions must be positive.');
        }
    }

    public static function fromRecord(MethodRecord $record): self
    {
        return new self(
            $record->methodId(),
            $record->userId(),
            $record->installation(),
            $record->providerKey(),
            $record->status(),
            $record->revision(),
        );
    }

    public function methodId(): MethodId { return $this->methodId; }
    public function userId(): UserId { return $this->userId; }
    public function installation(): InstallationBinding { return $this->installation; }
    public function providerKey(): ProviderKey { return $this->providerKey; }
    public function status(): MethodStatus { return $this->status; }
    public function revision(): int { return $this->revision; }

    public function matchesRecord(MethodRecord $record): bool
    {
        return $this->methodId->equals($record->methodId())
            && $this->userId->equals($record->userId())
            && $this->installation->equals($record->installation())
            && $this->providerKey->equals($record->providerKey())
            && $this->revision === $record->revision()
            && $record->status() === MethodStatus::ACTIVE;
    }
}
