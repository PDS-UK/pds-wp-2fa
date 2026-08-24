<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

use DateTimeImmutable;

final class RolePolicySetting
{
    public function __construct(
        private readonly string $roleKey,
        private readonly string $label,
        private readonly string $status,
        private readonly bool $enabled,
        private readonly int $gracePeriodSeconds,
        private readonly ?DateTimeImmutable $activatedAt = null,
    ) {
        if (preg_match('/^[a-z][a-z0-9_-]{0,63}$/', $roleKey) !== 1) {
            throw new \InvalidArgumentException('Role keys must be stable identifiers.');
        }
        if (!in_array($status, ['active', 'disabled', 'orphaned'], true)) {
            throw new \InvalidArgumentException('Invalid role policy status.');
        }
        if ($gracePeriodSeconds < 0 || $gracePeriodSeconds > 31536000) {
            throw new \InvalidArgumentException('Grace periods must be between 0 and 31536000 seconds.');
        }
        if ($status === 'active' && !$enabled) {
            throw new \InvalidArgumentException('Active role policies must be enabled.');
        }
    }

    public function roleKey(): string { return $this->roleKey; }
    public function label(): string { return $this->label; }
    public function status(): string { return $this->status; }
    public function enabled(): bool { return $this->enabled; }
    public function gracePeriodSeconds(): int { return $this->gracePeriodSeconds; }
    public function activatedAt(): ?DateTimeImmutable { return $this->activatedAt; }
    public function isEditable(): bool { return $this->status !== 'orphaned'; }

    /** @return array<string, mixed> */
    public function toSafeArray(): array
    {
        return [
            'role_key' => $this->roleKey,
            'label' => $this->label,
            'status' => $this->status,
            'enabled' => $this->enabled,
            'grace_period_seconds' => $this->gracePeriodSeconds,
            'activated_at' => $this->activatedAt?->format(DATE_ATOM),
        ];
    }
}
