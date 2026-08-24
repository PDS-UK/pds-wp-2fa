<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use DateTimeImmutable;
use PDS\WP2FA\Method\FriendlyLabel;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\LastUsedAt;
use PDS\WP2FA\Method\MethodDraft;
use PDS\WP2FA\Method\MethodRecord;
use PDS\WP2FA\Method\MethodStore;
use PDS\WP2FA\Method\MethodId;
use PDS\WP2FA\Method\MethodStatus;
use PDS\WP2FA\Method\ProviderData;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\Revocation;
use PDS\WP2FA\Method\UserId;
use PDS\WP2FA\Method\VerificationCommit;

final class MethodRepository implements MethodStore
{
    private Sql $sql;

    public function __construct(private Wpdb $db, private TableNames $tables)
    {
        $this->sql = new Sql($db);
    }

    public function create(MethodDraft $draft, DateTimeImmutable $at): MethodRecord
    {
        $scope = InstallationScope::fromMethod($draft->installation());
        $id = MethodId::random();
        $record = $this->insertMethod($id, $draft, $at, $scope);
        $this->persistProviderData($id, $draft->providerData(), $draft->userId(), $scope, $at);

        return $record;
    }

    public function find(UserId $userId, InstallationBinding $installation, MethodId $methodId): ?MethodRecord
    {
        return $this->read($userId, $installation, $methodId, false);
    }

    public function findForUpdate(UserId $userId, InstallationBinding $installation, MethodId $methodId): ?MethodRecord
    {
        return $this->read($userId, $installation, $methodId, true);
    }

    public function activeFor(UserId $userId, InstallationBinding $installation, ProviderKey $provider): array
    {
        $scope = InstallationScope::fromMethod($installation);
        $query = $this->db->prepare(
            "SELECT * FROM {$this->tables->get('methods')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND provider_key=%s AND status='active' ORDER BY created_at ASC",
            $scope->identityHash(), $scope->epoch(), $userId->value(), $provider->value(),
        );
        return array_map(fn (array $row): MethodRecord => $this->hydrate($row), $this->sql->rows($query, 'read active methods'));
    }

    public function markAuthenticated(MethodRecord $method, VerificationCommit $commit, DateTimeImmutable $at): void
    {
        if (!$method->providerKey()->equals($commit->providerKey()) || !$method->isActive()) {
            throw new PersistenceException('A verification commit does not match an active method.');
        }
        $scope = InstallationScope::fromMethod($method->installation());
        $query = $this->db->prepare(
            "UPDATE {$this->tables->get('methods')} SET last_used_at=%s, updated_at=%s, revision=revision+1 WHERE installation_identity_hash=%s AND installation_epoch=%d AND method_id=%s AND user_id=%d AND provider_key=%s AND status='active' AND revision=%d",
            Sql::utc($at), Sql::utc($at), $scope->identityHash(), $scope->epoch(), Sql::opaque16($method->methodId()->value()), $method->userId()->value(), $method->providerKey()->value(), $method->revision(),
        );
        if ($this->sql->execute($query, 'mark method authenticated') !== 1) {
            throw PersistenceException::compareAndSwapFailed('mark method authenticated');
        }
    }

    public function retainedCount(UserId $userId, InstallationBinding $installation): int
    {
        $scope = InstallationScope::fromMethod($installation);
        $query = $this->db->prepare(
            "SELECT COUNT(*) FROM {$this->tables->get('methods')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND status<>'revoked'",
            $scope->identityHash(), $scope->epoch(), $userId->value(),
        );
        $count = $this->db->get_var($query);
        if (!is_numeric($count)) {
            throw PersistenceException::queryFailed('count retained methods', $this->db->get_error());
        }
        return (int) $count;
    }

    public function revoke(MethodRecord $method, Revocation $revocation): void
    {
        $scope = InstallationScope::fromMethod($method->installation());
        $actorId = $revocation->actor()?->value();
        if ($actorId === null) {
            $query = $this->db->prepare(
                "UPDATE {$this->tables->get('methods')} SET status='revoked', revoked_at=%s, revoked_by=NULL, revoked_reason=%s, updated_at=%s, revision=revision+1 WHERE installation_identity_hash=%s AND installation_epoch=%d AND method_id=%s AND user_id=%d AND status<>'revoked' AND revision=%d",
                Sql::utc($revocation->at()), $revocation->reason()->value, Sql::utc($revocation->at()), $scope->identityHash(), $scope->epoch(), Sql::opaque16($method->methodId()->value()), $method->userId()->value(), $method->revision(),
            );
        } else {
            $query = $this->db->prepare(
                "UPDATE {$this->tables->get('methods')} SET status='revoked', revoked_at=%s, revoked_by=%d, revoked_reason=%s, updated_at=%s, revision=revision+1 WHERE installation_identity_hash=%s AND installation_epoch=%d AND method_id=%s AND user_id=%d AND status<>'revoked' AND revision=%d",
                Sql::utc($revocation->at()), $actorId, $revocation->reason()->value, Sql::utc($revocation->at()), $scope->identityHash(), $scope->epoch(), Sql::opaque16($method->methodId()->value()), $method->userId()->value(), $method->revision(),
            );
        }
        if ($this->sql->execute($query, 'revoke method') !== 1) {
            throw PersistenceException::compareAndSwapFailed('revoke method');
        }
    }

    public function replace(MethodRecord $old, MethodDraft $replacement, Revocation $revocation, DateTimeImmutable $at): MethodRecord
    {
        if (!$old->userId()->equals($replacement->userId()) || !$old->installation()->equals($replacement->installation())) {
            throw new PersistenceException('A replacement method must use the same user and installation binding.');
        }
        $new = $this->create($replacement, $at);
        $this->revoke($old, $revocation);

        return $new;
    }

    private function insertMethod(MethodId $id, MethodDraft $draft, DateTimeImmutable $at, InstallationScope $scope): MethodRecord
    {
        $query = $this->db->prepare(
            "INSERT INTO {$this->tables->get('methods')} (method_id,installation_identity_hash,installation_epoch,user_id,provider_key,provider_schema_version,label,status,created_at,updated_at,last_used_at,revoked_at,revoked_by,revoked_reason,revision) VALUES (%s,%s,%d,%d,%s,%d,%s,'active',%s,%s,NULL,NULL,NULL,NULL,1)",
            Sql::opaque16($id->value()), $scope->identityHash(), $scope->epoch(), $draft->userId()->value(), $draft->providerKey()->value(), $draft->schemaVersion(), $draft->label()->value(), Sql::utc($at), Sql::utc($at),
        );
        $this->sql->execute($query, 'create method');

        return new MethodRecord($id, $draft->userId(), $draft->installation(), $draft->providerKey(), $draft->schemaVersion(), $draft->label(), MethodStatus::ACTIVE, $at, $at, null, null, 1, LastUsedAt::never());
    }

    private function persistProviderData(MethodId $id, ProviderData $data, UserId $user, InstallationScope $scope, DateTimeImmutable $at): void
    {
        if ($data->toArray() === []) {
            return;
        }
        if ($data->schemaVersion() < 1) {
            throw new PersistenceException('Provider data has an invalid schema version.');
        }
        $values = $data->toArray();
        if (array_key_exists('secret', $values) || array_key_exists('plaintext', $values)) {
            throw new PersistenceException('Plaintext authenticator secrets cannot be persisted.');
        }
        if (($values['provider'] ?? null) === 'totp' || isset($values['secret_envelope'])) {
            $envelope = $values['secret_envelope'] ?? null;
            if (!is_string($envelope) || $envelope === '' || strlen($envelope) > 255) {
                throw new PersistenceException('The TOTP secret envelope is invalid.');
            }
            if (($values['algorithm'] ?? 'sha1') !== 'sha1' || (int) ($values['digits'] ?? 6) !== 6 || (int) ($values['period_seconds'] ?? 30) !== 30 || (int) ($values['t0'] ?? 0) !== 0) {
                throw new PersistenceException('The TOTP profile is invalid.');
            }
            $query = $this->db->prepare(
                "INSERT INTO {$this->tables->get('method_totp')} (installation_identity_hash,installation_epoch,method_id,secret_envelope,envelope_version,encryption_key_version,algorithm,digits,period_seconds,t0,last_accepted_step,created_at,updated_at) VALUES (%s,%s,%s,%s,%d,%s,%s,%d,%d,%d,NULL,%s,%s)",
                $scope->identityHash(), $scope->epoch(), Sql::opaque16($id->value()), $envelope, (int) ($values['envelope_version'] ?? 1), (string) ($values['encryption_key_version'] ?? 'unknown'), (string) ($values['algorithm'] ?? 'sha1'), (int) ($values['digits'] ?? 6), (int) ($values['period_seconds'] ?? 30), (int) ($values['t0'] ?? 0), Sql::utc($at), Sql::utc($at),
            );
            $this->sql->execute($query, 'create TOTP provider record');
        }
    }

    private function read(UserId $user, InstallationBinding $installation, MethodId $id, bool $forUpdate): ?MethodRecord
    {
        $scope = InstallationScope::fromMethod($installation);
        $query = $this->db->prepare(
            "SELECT * FROM {$this->tables->get('methods')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND method_id=%s" . ($forUpdate ? ' FOR UPDATE' : ''),
            $scope->identityHash(), $scope->epoch(), $user->value(), Sql::opaque16($id->value()),
        );
        $row = $this->sql->row($query, 'read method');
        return $row === null ? null : $this->hydrate($row);
    }

    private function hydrate(array $row): MethodRecord
    {
        $status = MethodStatus::from((string) $row['status']);
        $revokedAt = Sql::date($row['revoked_at'] ?? null);
        return new MethodRecord(
            MethodId::fromString(Sql::externalId((string) $row['method_id'])),
            UserId::fromInt((int) $row['user_id']),
            new InstallationBinding(bin2hex((string) $row['installation_identity_hash']), (int) $row['installation_epoch']),
            ProviderKey::fromString((string) $row['provider_key']),
            (int) $row['provider_schema_version'],
            FriendlyLabel::fromString((string) $row['label']),
            $status,
            new DateTimeImmutable((string) $row['created_at'], new \DateTimeZone('UTC')),
            new DateTimeImmutable((string) $row['updated_at'], new \DateTimeZone('UTC')),
            $revokedAt,
            isset($row['revoked_by']) && $row['revoked_by'] !== null ? UserId::fromInt((int) $row['revoked_by']) : null,
            (int) $row['revision'],
            ($row['last_used_at'] ?? null) !== null ? LastUsedAt::at(new DateTimeImmutable((string) $row['last_used_at'], new \DateTimeZone('UTC'))) : LastUsedAt::never(),
        );
    }
}
