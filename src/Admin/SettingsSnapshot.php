<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class SettingsSnapshot
{
    /** @param list<RolePolicySetting> $rolePolicies */
    public function __construct(
        private readonly bool $globalEnforcement,
        array $rolePolicies,
        private readonly int $auditRetentionDays,
        /** @var array<string, mixed> */
        private readonly array $deploymentStatus = [],
    ) {
        foreach ($rolePolicies as $policy) {
            if (!$policy instanceof RolePolicySetting) {
                throw new \InvalidArgumentException('Role policies must be typed settings.');
            }
        }
        if ($auditRetentionDays < 400 || $auditRetentionDays > 2555) {
            throw new \InvalidArgumentException('Audit retention must be between 400 and 2555 days.');
        }
        $this->rolePolicies = array_values($rolePolicies);
        self::assertSafeDeploymentStatus($deploymentStatus);
    }

    /** @var list<RolePolicySetting> */
    private readonly array $rolePolicies;

    public function globalEnforcement(): bool { return $this->globalEnforcement; }
    /** @return list<RolePolicySetting> */
    public function rolePolicies(): array { return $this->rolePolicies; }
    public function auditRetentionDays(): int { return $this->auditRetentionDays; }
    /** @return array<string, mixed> */
    public function deploymentStatus(): array { return $this->deploymentStatus; }

    public function role(string $roleKey): ?RolePolicySetting
    {
        foreach ($this->rolePolicies as $policy) {
            if ($policy->roleKey() === $roleKey) {
                return $policy;
            }
        }

        return null;
    }

    /** @return array<string, mixed> */
    public function toSafeArray(): array
    {
        return [
            'global_enforcement' => $this->globalEnforcement,
            'role_policy' => array_map(static fn (RolePolicySetting $policy): array => $policy->toSafeArray(), $this->rolePolicies),
            'audit_retention_days' => $this->auditRetentionDays,
            'deployment' => $this->deploymentStatus,
        ];
    }

    /** @param array<string, mixed> $status */
    private static function assertSafeDeploymentStatus(array $status): void
    {
        $allowed = [
            'environment_type', 'binding_state', 'identity_epoch', 'webauthn_available',
            'non_production_bypass', 'configured_fingerprint', 'binding_fingerprint',
        ];
        foreach ($status as $key => $value) {
            if (!is_string($key) || !in_array($key, $allowed, true)) {
                throw new AdminException('Deployment diagnostics contain an unsupported field.', 'unsafe_output');
            }
            if (!is_scalar($value) && $value !== null) {
                throw new AdminException('Deployment diagnostics contain unsafe data.', 'unsafe_output');
            }
            if (is_string($value) && strlen($value) > 128) {
                throw new AdminException('Deployment diagnostics contain unsafe data.', 'unsafe_output');
            }
        }
    }
}
