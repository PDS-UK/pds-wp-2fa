<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class RolePolicyResolution
{
    /** @param list<RolePolicyContribution> $contributingRoles @param list<UserRolePolicyAnchor> $anchorsToPersist */
    public function __construct(
        private bool $protected,
        private array $contributingRoles,
        private array $anchorsToPersist,
        private ?DateTimeImmutable $baseDeadline,
        private ?DateTimeImmutable $extensionUntil,
        private ?DateTimeImmutable $effectiveDeadline,
        private bool $overdue,
    ) {
    }

    public function isProtected(): bool { return $this->protected; }
    /** @return list<RolePolicyContribution> */
    public function contributingRoles(): array { return $this->contributingRoles; }
    /** @return list<UserRolePolicyAnchor> */
    public function anchorsToPersist(): array { return $this->anchorsToPersist; }
    public function baseDeadline(): ?DateTimeImmutable { return $this->baseDeadline; }
    public function extensionUntil(): ?DateTimeImmutable { return $this->extensionUntil; }
    public function effectiveDeadline(): ?DateTimeImmutable { return $this->effectiveDeadline; }
    public function isOverdue(): bool { return $this->overdue; }
}
