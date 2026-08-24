<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class RolePolicyLifecycleEvent
{
    /** @param array<string, scalar|null> $metadata */
    public function __construct(
        private string $type,
        private DateTimeImmutable $at,
        private ?RoleKey $roleKey = null,
        private array $metadata = [],
    ) {
        if ($type === '') {
            throw new \InvalidArgumentException('Lifecycle event types cannot be empty.');
        }
        $this->at = Time::utc($at);
    }

    public function type(): string { return $this->type; }
    public function at(): DateTimeImmutable { return $this->at; }
    public function roleKey(): ?RoleKey { return $this->roleKey; }
    /** @return array<string, scalar|null> */
    public function metadata(): array { return $this->metadata; }
}
