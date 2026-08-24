<?php

declare(strict_types=1);

namespace PDS\WP2FA\Runtime;

use PDS\WP2FA\Identity\IdentityBindingWriter;
use PDS\WP2FA\Identity\InstallationBinding;
use PDS\WP2FA\Method\TransactionManager;
use PDS\WP2FA\Persistence\Sql;
use PDS\WP2FA\Persistence\TableNames;
use PDS\WP2FA\Persistence\Wpdb;

/** Transactional installation-binding mutations used by operator tooling. */
final class WordPressIdentityBindingWriter implements IdentityBindingWriter
{
    public function __construct(
        private readonly Wpdb $db,
        private readonly TableNames $tables,
        private readonly ?TransactionManager $transactions = null,
    ) {
    }

    public function initialize(InstallationBinding $binding): void
    {
        $this->run(function () use ($binding): void {
            $existing = $this->db->get_var($this->db->prepare(
                "SELECT installation_id FROM {$this->tables->get('installations')} WHERE installation_id=%d",
                InstallationBinding::SINGLETON_ID,
            ));
            if ($existing !== null) {
                throw new \RuntimeException('The installation identity is already initialized.');
            }

            $this->insert($binding);
        });
    }

    public function rebind(InstallationBinding $binding): void
    {
        $this->run(fn (): null => $this->replaceBinding($binding));
    }

    public function rotate(InstallationBinding $binding): void
    {
        $this->run(fn (): null => $this->replaceBinding($binding));
    }

    private function insert(InstallationBinding $binding): void
    {
        $query = $this->db->prepare(
            "INSERT INTO {$this->tables->get('installations')} (installation_id,identity_hash,identity_epoch,environment_type,global_enforcement,audit_retention_days,bound_at,updated_at,schema_version) VALUES (%d,%s,%d,%s,1,400,UTC_TIMESTAMP(),UTC_TIMESTAMP(),%d)",
            InstallationBinding::SINGLETON_ID,
            $binding->identityHash(),
            $binding->epoch(),
            $binding->environment()->value(),
            InstallationBinding::SCHEMA_VERSION,
        );
        $this->execute($query, 'initialize installation identity');
    }

    private function replaceBinding(InstallationBinding $binding): null
    {
        $row = $this->db->get_row($this->db->prepare(
            "SELECT identity_hash, identity_epoch FROM {$this->tables->get('installations')} WHERE installation_id=%d",
            InstallationBinding::SINGLETON_ID,
        ));
        if (is_object($row)) {
            $row = get_object_vars($row);
        }
        if (!is_array($row) || !is_string($row['identity_hash'] ?? null)) {
            throw new \RuntimeException('The installation identity is not initialized.');
        }
        $oldHash = $row['identity_hash'];
        $oldEpoch = (int) ($row['identity_epoch'] ?? 0);

        $query = $this->db->prepare(
            "UPDATE {$this->tables->get('installations')} SET identity_hash=%s, identity_epoch=%d, environment_type=%s, updated_at=UTC_TIMESTAMP() WHERE installation_id=%d",
            $binding->identityHash(),
            $binding->epoch(),
            $binding->environment()->value(),
            InstallationBinding::SINGLETON_ID,
        );
        if ($this->execute($query, 'replace installation identity') !== 1) {
            throw new \RuntimeException('The installation identity is not initialized.');
        }

        // Preserve rows for auditability, but quarantine security state under
        // the new identity so no old factor or session can authorize a request.
        foreach (['sessions', 'challenges', 'admin_reauth_grants', 'maintenance_leases'] as $table) {
            $this->execute($this->db->prepare(
                "DELETE FROM {$this->tables->get($table)} WHERE installation_identity_hash=%s AND installation_epoch=%d",
                $oldHash,
                $oldEpoch,
            ), 'quarantine old security state');
        }

        return null;
    }

    private function execute(string $query, string $operation): int
    {
        return (new Sql($this->db))->execute($query, $operation);
    }

    /** @param callable(): mixed $operation */
    private function run(callable $operation): mixed
    {
        return $this->transactions === null ? $operation() : $this->transactions->transaction($operation);
    }
}
