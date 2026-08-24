<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use DateTimeImmutable;
use PDS\WP2FA\Method\SessionDigest;
use PDS\WP2FA\Method\SessionState;
use PDS\WP2FA\Method\SessionStore;
use PDS\WP2FA\Method\UserId;

final class SessionRepository implements SessionStore
{
    private Sql $sql;

    public function __construct(
        private Wpdb $db,
        private TableNames $tables,
        private ?InstallationScope $scope = null,
    )
    {
        $this->sql = new Sql($db);
    }

    public function ensurePending(
        UserId $user,
        string $sessionDigest,
        InstallationScope $scope,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $wordpressExpiresAt,
    ): void {
        $hash = Sql::opaque32($sessionDigest);
        $table = $this->tables->get('sessions');
        $query = $this->db->prepare(
            "INSERT INTO {$table} (installation_identity_hash,installation_epoch,user_id,session_token_hash,state,created_at,updated_at,wordpress_expires_at,satisfied_at,invalidated_at) VALUES (%s,%d,%d,%s,'pending',%s,%s,%s,NULL,NULL) ON DUPLICATE KEY UPDATE updated_at=VALUES(updated_at), wordpress_expires_at=VALUES(wordpress_expires_at), state=IF(state='invalidated','pending',state), invalidated_at=NULL",
            $scope->identityHash(),
            $scope->epoch(),
            $user->value(),
            $hash,
            Sql::utc($createdAt),
            Sql::utc($createdAt),
            Sql::utc($wordpressExpiresAt),
        );
        $this->sql->execute($query, 'create pending session');
    }

    public function state(UserId $userId, SessionDigest $session): SessionState
    {
        return $this->stateFor($userId, $session, $this->scope);
    }

    public function stateFor(UserId $userId, SessionDigest $session, ?InstallationScope $scope): SessionState
    {
        if ($scope === null) {
            throw new \InvalidArgumentException('Session state reads require an installation scope.');
        }
        $row = $this->row($scope, $userId, $session, false);

        return $row === null ? SessionState::PENDING : SessionState::from((string) $row['state']);
    }

    public function satisfy(UserId $userId, SessionDigest $session): void
    {
        $scope = $this->scopeOrThrow();
        $this->satisfyFor($userId, $session, $scope);
    }

    public function satisfyFor(UserId $userId, SessionDigest $session, InstallationScope $scope, ?DateTimeImmutable $at = null): void
    {
        $at ??= new DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $hash = Sql::opaque32($session->value());
        $query = $this->db->prepare(
            "UPDATE {$this->tables->get('sessions')} SET state='satisfied', satisfied_at=%s, updated_at=%s WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND session_token_hash=%s AND state='pending'",
            Sql::utc($at), Sql::utc($at), $scope->identityHash(), $scope->epoch(), $userId->value(), $hash,
        );
        $affected = $this->sql->execute($query, 'satisfy session');
        if ($affected !== 1) {
            $row = $this->row($scope, $userId, $session, false);
            if ($row === null || ($row['state'] ?? null) !== SessionState::SATISFIED->value) {
                throw PersistenceException::compareAndSwapFailed('satisfy session');
            }
        }
    }

    public function invalidate(UserId $userId, SessionDigest $session): void
    {
        $scope = $this->scopeOrThrow();
        $this->invalidateFor($userId, $session, $scope);
    }

    public function invalidateFor(UserId $userId, SessionDigest $session, InstallationScope $scope, ?DateTimeImmutable $at = null): void
    {
        $at ??= new DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $query = $this->db->prepare(
            "UPDATE {$this->tables->get('sessions')} SET state='invalidated', invalidated_at=%s, updated_at=%s WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND session_token_hash=%s AND state<>'invalidated'",
            Sql::utc($at), Sql::utc($at), $scope->identityHash(), $scope->epoch(), $userId->value(), Sql::opaque32($session->value()),
        );
        $this->sql->execute($query, 'invalidate session');
    }

    /** @return array<string,mixed>|null */
    private function row(InstallationScope $scope, UserId $user, SessionDigest $session, bool $forUpdate): ?array
    {
        $query = $this->db->prepare(
            "SELECT * FROM {$this->tables->get('sessions')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND session_token_hash=%s" . ($forUpdate ? ' FOR UPDATE' : ''),
            $scope->identityHash(), $scope->epoch(), $user->value(), Sql::opaque32($session->value()),
        );

        return $this->sql->row($query, 'read session');
    }

    private function scopeOrThrow(): InstallationScope
    {
        if ($this->scope === null) {
            throw new \InvalidArgumentException('Session operations require an installation scope.');
        }

        return $this->scope;
    }
}
