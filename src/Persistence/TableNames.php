<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

/** Fixed table map; request input can never select a table. */
final class TableNames
{
    /** @var list<string> */
    public const SUFFIXES = [
        'installations', 'schema_versions', 'maintenance_leases',
        'role_policies', 'user_role_policies', 'enrollment_cycles', 'deadline_extensions',
        'methods', 'method_totp', 'method_webauthn', 'recovery_generations', 'recovery_codes',
        'challenges', 'sessions', 'admin_reauth_grants', 'rate_limits', 'audit_events',
    ];

    /** @var array<string,string> */
    private array $tables = [];

    public function __construct(string $prefix)
    {
        if ($prefix === '' || preg_match('/\A[A-Za-z0-9_$-]+\z/', $prefix) !== 1) {
            throw new \InvalidArgumentException('The database prefix is invalid.');
        }

        foreach (self::SUFFIXES as $suffix) {
            $this->tables[$suffix] = $prefix . 'pds_wp_2fa_' . $suffix;
        }
    }

    public function get(string $suffix): string
    {
        if (!isset($this->tables[$suffix])) {
            throw new \InvalidArgumentException('Unknown fixed persistence table.');
        }

        return $this->tables[$suffix];
    }

    /** @return array<string,string> */
    public function all(): array { return $this->tables; }
}
