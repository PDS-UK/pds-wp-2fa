<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

final class RolePolicyLifecycleResult
{
    /** @param array<string, RolePolicy> $policies @param list<RolePolicyLifecycleEvent> $events */
    public function __construct(private array $policies, private array $events = [])
    {
    }

    public function policy(?RoleKey $roleKey = null): ?RolePolicy
    {
        if ($roleKey !== null) {
            return $this->policies[$roleKey->value()] ?? null;
        }

        return count($this->policies) === 1 ? reset($this->policies) : null;
    }

    /** @return list<RolePolicyLifecycleEvent> */
    public function events(): array { return $this->events; }

    /** @return list<RolePolicy> */
    public function policies(): array { return array_values($this->policies); }
}
