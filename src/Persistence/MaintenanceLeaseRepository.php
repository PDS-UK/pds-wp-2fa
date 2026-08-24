<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use DateTimeImmutable;

final class MaintenanceLeaseRepository
{
    private Sql $sql;

    public function __construct(private Wpdb $db, private TableNames $tables, private InstallationScope $scope)
    {
        $this->sql = new Sql($db);
    }

    public function acquire(string $leaseKey, string $ownerToken, DateTimeImmutable $at, DateTimeImmutable $expiresAt): bool
    {
        if ($leaseKey === '' || strlen($leaseKey) > 64 || $expiresAt <= $at) {
            throw new \InvalidArgumentException('Invalid maintenance lease.');
        }
        $ownerHash = hash('sha256', $ownerToken, true);
        $query = $this->db->prepare(
            "INSERT INTO {$this->tables->get('maintenance_leases')} (lease_key,installation_identity_hash,installation_epoch,owner_token_hash,cursor_created_at,cursor_event_id,acquired_at,expires_at,updated_at) VALUES (%s,%s,%d,%s,NULL,NULL,%s,%s,%s) ON DUPLICATE KEY UPDATE owner_token_hash=IF(expires_at<=VALUES(acquired_at),VALUES(owner_token_hash),owner_token_hash), acquired_at=IF(expires_at<=VALUES(acquired_at),VALUES(acquired_at),acquired_at), expires_at=IF(expires_at<=VALUES(acquired_at),VALUES(expires_at),expires_at), updated_at=VALUES(updated_at)",
            $leaseKey, $this->scope->identityHash(), $this->scope->epoch(), $ownerHash, Sql::utc($at), Sql::utc($expiresAt), Sql::utc($at),
        );
        $this->sql->execute($query, 'acquire maintenance lease');
        $row = $this->sql->row($this->db->prepare("SELECT owner_token_hash,expires_at FROM {$this->tables->get('maintenance_leases')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND lease_key=%s", $this->scope->identityHash(), $this->scope->epoch(), $leaseKey), 'read maintenance lease');
        return $row !== null && isset($row['owner_token_hash']) && hash_equals((string) $row['owner_token_hash'], $ownerHash) && new DateTimeImmutable((string) $row['expires_at'], new \DateTimeZone('UTC')) > $at;
    }

    public function release(string $leaseKey, string $ownerToken, DateTimeImmutable $at): void
    {
        $query = $this->db->prepare("DELETE FROM {$this->tables->get('maintenance_leases')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND lease_key=%s AND owner_token_hash=%s", $this->scope->identityHash(), $this->scope->epoch(), $leaseKey, hash('sha256', $ownerToken, true));
        $this->sql->execute($query, 'release maintenance lease');
    }

    public function updateCursor(string $leaseKey, string $ownerToken, ?DateTimeImmutable $createdAt, ?string $eventId, DateTimeImmutable $at): void
    {
        $query = $this->db->prepare("UPDATE {$this->tables->get('maintenance_leases')} SET cursor_created_at=%s,cursor_event_id=%s,updated_at=%s WHERE installation_identity_hash=%s AND installation_epoch=%d AND lease_key=%s AND owner_token_hash=%s AND expires_at>%s", $createdAt === null ? null : Sql::utc($createdAt), $eventId === null ? null : Sql::opaque16($eventId), Sql::utc($at), $this->scope->identityHash(), $this->scope->epoch(), $leaseKey, hash('sha256', $ownerToken, true), Sql::utc($at));
        if ($this->sql->execute($query, 'update maintenance cursor') !== 1) {
            throw PersistenceException::compareAndSwapFailed('update maintenance cursor');
        }
    }
}
