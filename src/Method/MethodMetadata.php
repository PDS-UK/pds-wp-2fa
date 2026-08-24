<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

use DateTimeImmutable;

final class MethodMetadata
{
    public function __construct(
        private FriendlyLabel $label,
        private DateTimeImmutable $createdAt,
        private DateTimeImmutable $updatedAt,
        private LastUsedAt $lastUsedAt,
    ) {
        if ($updatedAt < $createdAt) {
            throw new \InvalidArgumentException('Method metadata cannot move backwards in time.');
        }
    }

    public function label(): FriendlyLabel { return $this->label; }
    public function createdAt(): DateTimeImmutable { return $this->createdAt; }
    public function updatedAt(): DateTimeImmutable { return $this->updatedAt; }
    public function lastUsedAt(): LastUsedAt { return $this->lastUsedAt; }
}
