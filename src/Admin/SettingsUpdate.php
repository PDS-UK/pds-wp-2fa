<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class SettingsUpdate
{
    /** @param array<string, array{enabled: bool, grace_period_seconds: int}> $rolePolicies */
    private function __construct(
        private readonly bool $globalEnforcement,
        private readonly array $rolePolicies,
        private readonly int $auditRetentionDays,
    ) {
    }

    /** @param array<string, mixed> $submitted */
    public static function fromSubmitted(SettingsSnapshot $current, array $submitted): self
    {
        $expected = ['global_enforcement', 'role_policy', 'audit_retention_days'];
        foreach (array_keys($submitted) as $key) {
            if (!in_array($key, $expected, true)) {
                throw new AdminException('Settings contain an unknown field.', 'validation_error');
            }
        }
        foreach ($expected as $key) {
            if (!array_key_exists($key, $submitted)) {
                throw new AdminException('Settings must be submitted as a complete state.', 'validation_error');
            }
        }

        $global = self::boolean($submitted['global_enforcement']);
        $retention = filter_var($submitted['audit_retention_days'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 400, 'max_range' => 2555]]);
        if ($retention === false) {
            throw new AdminException('Audit retention must be between 400 and 2555 days.', 'validation_error');
        }
        if (!is_array($submitted['role_policy'])) {
            throw new AdminException('Role policies must be an array.', 'validation_error');
        }

        $policies = [];
        $editableKeys = [];
        foreach ($current->rolePolicies() as $currentPolicy) {
            if ($currentPolicy->isEditable()) {
                $editableKeys[] = $currentPolicy->roleKey();
            }
        }
        foreach (array_keys($submitted['role_policy']) as $roleKey) {
            if (!is_string($roleKey) || !in_array($roleKey, $editableKeys, true)) {
                throw new AdminException('Role policies may only address currently discovered roles.', 'validation_error');
            }
        }
        if (count($submitted['role_policy']) !== count($editableKeys)) {
            throw new AdminException('Role policies must be submitted as a complete state.', 'validation_error');
        }

        foreach ($editableKeys as $roleKey) {
            $value = $submitted['role_policy'][$roleKey] ?? null;
            if (!is_array($value) || !array_key_exists('enabled', $value) || !array_key_exists('grace_period_seconds', $value)) {
                throw new AdminException('Each role policy requires enabled and grace-period fields.', 'validation_error');
            }
            $grace = filter_var($value['grace_period_seconds'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 31536000]]);
            if ($grace === false) {
                throw new AdminException('Grace periods must be between 0 and 31536000 seconds.', 'validation_error');
            }
            $policies[$roleKey] = [
                'enabled' => self::boolean($value['enabled']),
                'grace_period_seconds' => $grace,
            ];
        }

        return new self($global, $policies, $retention);
    }

    public function globalEnforcement(): bool { return $this->globalEnforcement; }
    /** @return array<string, array{enabled: bool, grace_period_seconds: int}> */
    public function rolePolicies(): array { return $this->rolePolicies; }
    public function auditRetentionDays(): int { return $this->auditRetentionDays; }

    private static function boolean(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if ($value === 1 || $value === '1' || $value === 'on' || $value === 'true') {
            return true;
        }
        if ($value === 0 || $value === '0' || $value === 'off' || $value === 'false') {
            return false;
        }

        throw new AdminException('Boolean settings must be explicit.', 'validation_error');
    }
}
