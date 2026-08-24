<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class RolePolicyResolutionInput
{
    /** @param list<RoleKey> $currentRoles @param list<RolePolicy> $policies @param list<UserRolePolicyAnchor> $anchors @param list<GraceExtension> $extensions @param array<string, DateTimeImmutable> $firstObservedAtByRole */
    public function __construct(
        private int $userId,
        private array $currentRoles,
        private array $policies,
        private array $anchors,
        private bool $enrolled,
        private EnrollmentCycleId $cycle,
        private array $extensions,
        private DateTimeImmutable $now,
        private array $firstObservedAtByRole = [],
    ) {
        if ($userId < 1) {
            throw new \InvalidArgumentException('A user ID must be positive.');
        }
        foreach ($currentRoles as $role) {
            if (!$role instanceof RoleKey) {
                throw new \InvalidArgumentException('Current roles must be RoleKey values.');
            }
        }
        foreach ($policies as $policy) {
            if (!$policy instanceof RolePolicy) {
                throw new \InvalidArgumentException('Policies must be RolePolicy values.');
            }
        }
        foreach ($anchors as $anchor) {
            if (!$anchor instanceof UserRolePolicyAnchor) {
                throw new \InvalidArgumentException('Anchors must be UserRolePolicyAnchor values.');
            }
        }
        foreach ($extensions as $extension) {
            if (!$extension instanceof GraceExtension) {
                throw new \InvalidArgumentException('Extensions must be GraceExtension values.');
            }
        }
        foreach ($firstObservedAtByRole as $roleKey => $observedAt) {
            if (!is_string($roleKey) || !$observedAt instanceof DateTimeImmutable) {
                throw new \InvalidArgumentException('First-observed role timestamps must be keyed DateTimeImmutable values.');
            }
        }
        $this->now = Time::utc($now);
    }

    public function userId(): int { return $this->userId; }
    /** @return list<RoleKey> */
    public function currentRoles(): array { return $this->currentRoles; }
    /** @return list<RolePolicy> */
    public function policies(): array { return $this->policies; }
    /** @return list<UserRolePolicyAnchor> */
    public function anchors(): array { return $this->anchors; }
    public function enrolled(): bool { return $this->enrolled; }
    public function cycle(): EnrollmentCycleId { return $this->cycle; }
    /** @return list<GraceExtension> */
    public function extensions(): array { return $this->extensions; }
    public function now(): DateTimeImmutable { return $this->now; }
    public function firstObservedAt(RoleKey $roleKey): ?DateTimeImmutable
    {
        $observedAt = $this->firstObservedAtByRole[$roleKey->value()] ?? null;

        return $observedAt instanceof DateTimeImmutable ? Time::utc($observedAt) : null;
    }
}
