<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use DateTimeImmutable;

final class MigrationRunner
{
    /** @param callable(string):mixed|null $dbDelta */
    public function __construct(
        private Wpdb $db,
        private TableNames $tables,
        private SchemaDefinition $schema,
        private $dbDelta = null,
        private string $migrationKey = 'pds_wp_2fa',
    ) {
        if ($dbDelta !== null && !is_callable($dbDelta)) {
            throw new \InvalidArgumentException('dbDelta runner must be callable.');
        }
    }

    public function migrate(?DateTimeImmutable $at = null): void
    {
        $at ??= new DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $statements = $this->schema->statements();
        $delta = $this->dbDelta ?? $this->wordpressDbDelta();

        // schema_versions is always the first additive DDL and intentionally
        // carries no installation binding, so a fresh database can be prepared.
        ($delta)($statements[0]);
        $this->mark('failed', 0, 'migration_running', $at);

        try {
            foreach (array_slice($statements, 1) as $statement) {
                ($delta)($statement);
            }
            $this->mark('ready', SchemaDefinition::VERSION, null, $at);
        } catch (\Throwable $e) {
            $this->mark('failed', 0, 'migration_failed', $at);
            throw new PersistenceException('The security schema migration failed.', 0, $e);
        }
    }

    public function isReady(): bool
    {
        $sql = $this->db->prepare(
            "SELECT schema_version, state FROM {$this->tables->get('schema_versions')} WHERE migration_key = %s",
            $this->migrationKey,
        );
        $row = (new Sql($this->db))->row($sql, 'read schema version');

        return $row !== null
            && ($row['state'] ?? null) === 'ready'
            && (int) ($row['schema_version'] ?? 0) >= SchemaDefinition::VERSION;
    }

    private function mark(string $state, int $version, ?string $error, DateTimeImmutable $at): void
    {
        $sql = $this->db->prepare(
            "INSERT INTO {$this->tables->get('schema_versions')} (migration_key,schema_version,state,updated_at,last_error_code) VALUES (%s,%d,%s,%s,%s) ON DUPLICATE KEY UPDATE schema_version=VALUES(schema_version), state=VALUES(state), updated_at=VALUES(updated_at), last_error_code=VALUES(last_error_code)",
            $this->migrationKey,
            $version,
            $state,
            Sql::utc($at),
            $error,
        );
        (new Sql($this->db))->execute($sql, 'write schema version');
    }

    /** @return callable(string):mixed */
    private function wordpressDbDelta(): callable
    {
        if (!function_exists('dbDelta')) {
            if (defined('ABSPATH')) {
                $upgrade = constant('ABSPATH') . 'wp-admin/includes/upgrade.php';
                if (is_file($upgrade)) {
                    require_once $upgrade;
                }
            }
        }
        if (!function_exists('dbDelta')) {
            throw new PersistenceException('WordPress dbDelta() is unavailable.');
        }

        return static fn (string $statement): mixed => dbDelta($statement);
    }
}
