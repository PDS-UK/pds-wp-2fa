<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use DateTimeImmutable;
use PDS\WP2FA\Crypto\RecoveryCodeRecord;
use PDS\WP2FA\Crypto\RecoveryCodeStore;

/**
 * Recovery codes are queried by verifier hash and consumed by a conditional
 * update. The raw candidate is never passed to this repository.
 */
final class RecoveryCodeRepository implements RecoveryCodeStore
{
    private Sql $sql;

    public function __construct(private Wpdb $db, private TableNames $tables, private InstallationScope $scope, private ?WpdbTransactionManager $transactions = null)
    {
        $this->sql = new Sql($db);
    }

    public function unused(string $generationId): iterable
    {
        $query = $this->db->prepare(
            "SELECT code_id,code_verifier FROM {$this->tables->get('recovery_codes')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND generation_id=%s AND used_at IS NULL AND revoked_at IS NULL AND code_verifier IS NOT NULL",
            $this->scope->identityHash(), $this->scope->epoch(), Sql::opaque16($generationId),
        );
        foreach ($this->sql->rows($query, 'read unused recovery codes') as $row) {
            if (!is_string($row['code_verifier'] ?? null) || !is_string($row['code_id'] ?? null)) {
                continue;
            }
            yield new RecoveryCodeRecord(Sql::externalId($row['code_id']), $row['code_verifier']);
        }
    }

    public function consumeIfUnused(string $codeId): bool
    {
        $operation = function () use ($codeId): bool {
            $at = new DateTimeImmutable('now', new \DateTimeZone('UTC'));
            $query = $this->db->prepare(
                "UPDATE {$this->tables->get('recovery_codes')} SET used_at=%s WHERE installation_identity_hash=%s AND installation_epoch=%d AND code_id=%s AND used_at IS NULL AND revoked_at IS NULL AND code_verifier IS NOT NULL",
                Sql::utc($at), $this->scope->identityHash(), $this->scope->epoch(), Sql::opaque16($codeId),
            );
            if ($this->sql->execute($query, 'consume recovery code') !== 1) {
                return false;
            }
            $exhaust = $this->db->prepare(
                "UPDATE {$this->tables->get('recovery_generations')} g SET status='exhausted', exhausted_at=%s, active_marker=NULL, updated_at=%s WHERE g.installation_identity_hash=%s AND g.installation_epoch=%d AND EXISTS (SELECT 1 FROM {$this->tables->get('recovery_codes')} c WHERE c.installation_identity_hash=g.installation_identity_hash AND c.installation_epoch=g.installation_epoch AND c.generation_id=g.generation_id AND c.code_id=%s) AND NOT EXISTS (SELECT 1 FROM {$this->tables->get('recovery_codes')} c2 WHERE c2.installation_identity_hash=g.installation_identity_hash AND c2.installation_epoch=g.installation_epoch AND c2.generation_id=g.generation_id AND c2.used_at IS NULL AND c2.revoked_at IS NULL)",
                Sql::utc($at), Sql::utc($at), $this->scope->identityHash(), $this->scope->epoch(), Sql::opaque16($codeId),
            );
            $this->sql->execute($exhaust, 'exhaust recovery generation');

            return true;
        };

        return $this->transactions === null ? $operation() : $this->transactions->transaction($operation);
    }

    /** @param list<array{id:string,hash:string}> $codes */
    public function createGeneration(string $generationId, int $userId, string $methodId, array $codes, DateTimeImmutable $at): void
    {
        if (count($codes) !== 10) {
            throw new \InvalidArgumentException('A recovery generation must contain exactly ten codes.');
        }
        $generation = Sql::opaque16($generationId);
        $query = $this->db->prepare(
            "INSERT INTO {$this->tables->get('recovery_generations')} (generation_id,installation_identity_hash,installation_epoch,user_id,method_id,status,active_marker,created_at,exhausted_at,revoked_at,updated_at) VALUES (%s,%s,%d,%d,%s,'active','Y',%s,NULL,NULL,%s) ON DUPLICATE KEY UPDATE status='revoked', active_marker=NULL, revoked_at=VALUES(updated_at), updated_at=VALUES(updated_at)",
            $generation, $this->scope->identityHash(), $this->scope->epoch(), $userId, Sql::opaque16($methodId), Sql::utc($at), Sql::utc($at),
        );
        $this->sql->execute($query, 'create recovery generation');
        foreach ($codes as $code) {
            if (!isset($code['id'], $code['hash']) || $code['hash'] === '') {
                throw new \InvalidArgumentException('Recovery code rows require a non-empty password hash.');
            }
            $insert = $this->db->prepare(
                "INSERT INTO {$this->tables->get('recovery_codes')} (code_id,installation_identity_hash,installation_epoch,generation_id,user_id,code_verifier,created_at,used_at,revoked_at) VALUES (%s,%s,%d,%s,%d,%s,%s,NULL,NULL)",
                Sql::opaque16($code['id']), $this->scope->identityHash(), $this->scope->epoch(), $generation, $userId, $code['hash'], Sql::utc($at),
            );
            $this->sql->execute($insert, 'create recovery code');
        }
    }

    public function revokeGenerationsForUser(int $userId, DateTimeImmutable $at): void
    {
        $query = $this->db->prepare(
            "UPDATE {$this->tables->get('recovery_generations')} SET status='revoked', active_marker=NULL, revoked_at=%s, updated_at=%s WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND status='active'",
            Sql::utc($at), Sql::utc($at), $this->scope->identityHash(), $this->scope->epoch(), $userId,
        );
        $this->sql->execute($query, 'revoke recovery generations');
        $codes = $this->db->prepare(
            "UPDATE {$this->tables->get('recovery_codes')} SET revoked_at=%s, code_verifier=NULL WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND revoked_at IS NULL",
            Sql::utc($at), $this->scope->identityHash(), $this->scope->epoch(), $userId,
        );
        $this->sql->execute($codes, 'revoke recovery codes');
    }
}
