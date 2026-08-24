<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class SafeMetadata
{
    /** @var array<string, mixed> */
    private array $values;

    /** @param array<string, mixed> $values */
    private function __construct(array $values)
    {
        $this->values = $values;
    }

    /** @param array<string, mixed> $values */
    public static function forEvent(string $eventType, array $values): self
    {
        $allowed = self::allowedKeys($eventType);
        foreach ($values as $key => $value) {
            if (!is_string($key) || !in_array($key, $allowed, true)) {
                throw new AdminException('Audit metadata contains an unsupported field.', 'unsafe_metadata');
            }
            self::assertSafeValue($value);
        }

        return new self($values);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->values;
    }

    /** @return list<string> */
    private static function allowedKeys(string $eventType): array
    {
        return match ($eventType) {
            'global_enforcement_changed' => ['old_enabled', 'new_enabled', 'environment_type'],
            'role_policy_enabled', 'role_policy_disabled', 'role_policy_reenabled' => [
                'role_key', 'grace_period_seconds',
            ],
            'role_policy_grace_changed' => ['role_key', 'old_seconds', 'new_seconds'],
            'retention_policy_changed' => ['old_days', 'new_days'],
            'grace_extension_granted' => [
                'target_user_id', 'extension_seconds', 'previous_deadline', 'new_deadline',
            ],
            'admin_sessions_reset' => ['target_user_id'],
            'admin_enrollment_reset' => ['target_user_id', 'old_method_count', 'new_state'],
            'method_revoked' => ['target_user_id'],
            'recovery_generation_revoked' => ['target_user_id'],
            'identity_status_mismatch' => ['status', 'environment_type'],
            'audit_retention_run' => ['deleted_count', 'eligible_count', 'dry_run'],
            'admin_reauth_succeeded', 'admin_reauth_failed' => ['scope'],
            'admin_authorization_denied' => ['capability', 'target_user_id'],
            default => throw new AdminException('Unknown audit event type.', 'unsafe_metadata'),
        };
    }

    private static function assertSafeValue(mixed $value): void
    {
        if (is_bool($value) || is_int($value) || $value === null) {
            return;
        }

        if (is_string($value) && strlen($value) <= 128 && !preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value)) {
            return;
        }

        throw new AdminException('Audit metadata contains an unsafe value.', 'unsafe_metadata');
    }
}
