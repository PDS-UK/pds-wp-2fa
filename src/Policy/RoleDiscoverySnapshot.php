<?php

declare(strict_types=1);

namespace PDS\WP2FA\Policy;

use DateTimeImmutable;

final class RoleDiscoverySnapshot
{
    /** @var DateTimeImmutable */
    private $observedAt;

    /** @var array<string, string> */
    private $roleLabels;

    /**
     * @param array<string, string> $roleLabels
     */
    public static function fromRoleLabels(array $roleLabels, DateTimeImmutable $observedAt): self
    {
        $normalized = [];

        foreach ($roleLabels as $roleKey => $label) {
            if (!is_string($roleKey) || !is_string($label)) {
                throw new \InvalidArgumentException('Role discovery labels must be string keyed and valued.');
            }

            $normalized[$roleKey] = $label;
        }

        ksort($normalized, SORT_STRING);

        return new self(Time::utc($observedAt), $normalized);
    }

    /**
     * @param array<string, string> $roleLabels
     */
    private function __construct(DateTimeImmutable $observedAt, array $roleLabels)
    {
        $this->observedAt = $observedAt;
        $this->roleLabels = $roleLabels;
    }

    public function observedAt(): DateTimeImmutable
    {
        return $this->observedAt;
    }

    /**
     * @return list<RoleKey>
     */
    public function roleKeys(): array
    {
        return array_map(static function (string $roleKey): RoleKey {
            return new RoleKey($roleKey);
        }, array_keys($this->roleLabels));
    }

    public function has(RoleKey $roleKey): bool
    {
        return array_key_exists($roleKey->value(), $this->roleLabels);
    }

    public function labelFor(RoleKey $roleKey): string
    {
        if (!$this->has($roleKey)) {
            throw new \OutOfBoundsException('The role key is not present in this discovery snapshot.');
        }

        return $this->roleLabels[$roleKey->value()];
    }

    /**
     * @return array<string, string>
     */
    public function roleLabels(): array
    {
        return $this->roleLabels;
    }
}
