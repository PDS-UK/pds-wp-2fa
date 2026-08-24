<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class SafeOutput
{
    /** @param array<string, mixed> $row */
    public static function userRow(array $row): array
    {
        $allowed = [
            'user_id', 'user_login', 'role_keys', 'role_labels', 'policy_state',
            'contributing_role_keys', 'base_deadline', 'effective_deadline',
            'enrollment_cycle_state', 'active_method_counts', 'recovery_unused_count',
            'methods',
        ];

        return self::pick($row, $allowed);
    }

    /** @param array<string, mixed> $row */
    public static function auditRow(array $row): array
    {
        $allowed = [
            'event_type', 'severity', 'occurred_at', 'actor_kind', 'actor_user_id',
            'source', 'target_user_id', 'role_key', 'method_id', 'installation_fingerprint',
            'installation_epoch', 'outcome', 'reason_code', 'safe_metadata',
            'schema_version', 'correlation_id_hash',
        ];

        return self::pick($row, $allowed);
    }

    /** @param array<string, mixed> $row @param list<string> $allowed */
    private static function pick(array $row, array $allowed): array
    {
        $safe = [];
        foreach ($allowed as $key) {
            if (!array_key_exists($key, $row)) {
                continue;
            }
            self::assertRenderable($row[$key], 0);
            $safe[$key] = $row[$key];
        }

        return $safe;
    }

    private static function assertRenderable(mixed $value, int $depth): void
    {
        if ($depth > 2) {
            throw new AdminException('Status output is too deeply nested.', 'unsafe_output');
        }
        if (is_string($value)) {
            if (strlen($value) > 512 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value)) {
                throw new AdminException('Status output contains unsafe text.', 'unsafe_output');
            }
            return;
        }
        if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return;
        }
        if (is_array($value)) {
            foreach ($value as $nested) {
                self::assertRenderable($nested, $depth + 1);
            }
            return;
        }

        throw new AdminException('Status output contains unsafe data.', 'unsafe_output');
    }
}
