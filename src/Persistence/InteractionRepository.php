<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use DateTimeImmutable;
use PDS\WP2FA\Method\Clock;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\Interaction;
use PDS\WP2FA\Method\InteractionId;
use PDS\WP2FA\Method\InteractionPurpose;
use PDS\WP2FA\Method\InteractionReference;
use PDS\WP2FA\Method\InteractionStatus;
use PDS\WP2FA\Method\InteractionStore;
use PDS\WP2FA\Method\MethodId;
use PDS\WP2FA\Method\MethodSnapshot;
use PDS\WP2FA\Method\MethodSnapshotCollection;
use PDS\WP2FA\Method\MethodStatus;
use PDS\WP2FA\Method\PolicySnapshot;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\ProviderPublicPayload;
use PDS\WP2FA\Method\ProviderServerState;
use PDS\WP2FA\Method\ProviderStart;
use PDS\WP2FA\Method\ServerChallenge;
use PDS\WP2FA\Method\SessionDigest;
use PDS\WP2FA\Method\UserId;

final class InteractionRepository implements InteractionStore
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

    public function create(Interaction $interaction): void
    {
        $scope = InstallationScope::fromMethod($interaction->installation());
        $snapshot = [];
        foreach ($interaction->methodSnapshot()->all() as $method) {
            $snapshot[] = [
                'id' => $method->methodId()->value(),
                'user_id' => $method->userId()->value(),
                'provider' => $method->providerKey()->value(),
                'status' => $method->status()->value,
                'revision' => $method->revision(),
            ];
        }
        $referenceId = hex2bin($interaction->id()->value());
        $challenge = Sql::opaque32($interaction->challenge()->value());
        $payload = $interaction->start()->serverState()->toArray();
        // The domain contract requires the opaque reference when a row is
        // hydrated. It is not a credential or challenge; it is kept inside
        // the provider-state envelope solely because the schema stores only
        // its SHA-256 interaction_id_hash.
        $payload['__pds_interaction_reference'] = $interaction->reference()->value();
        $payload['__pds_policy_snapshot'] = $interaction->policy()->toArray();
        $methodId = $interaction->methodSnapshot()->all()[0]->methodId()->value() ?? null;
        $methodBytes = $methodId === null ? null : Sql::opaque16($methodId);
        $query = $this->db->prepare(
            "INSERT INTO {$this->tables->get('challenges')} (interaction_id_hash,installation_identity_hash,installation_epoch,user_id,session_token_hash,purpose,provider_key,method_id,allowed_method_ids,server_challenge,provider_state,provider_state_version,created_at,expires_at,consumed_at,revoked_at,attempt_count) VALUES (%s,%s,%d,%d,%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,NULL,NULL,%d)",
            $referenceId,
            $scope->identityHash(), $scope->epoch(), $interaction->userId()->value(), Sql::opaque32($interaction->session()->value()),
            $interaction->purpose()->value, $interaction->providerKey()->value(), $methodBytes,
            Sql::json($snapshot), $challenge, Sql::json($payload), 1,
            Sql::utc($interaction->createdAt()), Sql::utc($interaction->expiresAt()), 0,
        );
        $this->sql->execute($query, 'create interaction');
    }

    public function find(InteractionId $id): ?Interaction
    {
        $scope = $this->scopeOrThrow();
        return $this->findForScope($id, $scope);
    }

    public function findForScope(InteractionId $id, InstallationScope $scope, ?Clock $clock = null): ?Interaction
    {
        $row = $this->row($id, $scope, false);

        return $row === null ? null : $this->hydrate($row, $scope, $clock);
    }

    public function findForUpdate(InteractionId $id): ?Interaction
    {
        $scope = $this->scopeOrThrow();
        return $this->findForUpdateForScope($id, $scope);
    }

    public function findForUpdateForScope(InteractionId $id, InstallationScope $scope, ?Clock $clock = null): ?Interaction
    {
        $row = $this->row($id, $scope, true);

        return $row === null ? null : $this->hydrate($row, $scope, $clock);
    }

    public function consume(Interaction $interaction, DateTimeImmutable $at): void
    {
        $scope = InstallationScope::fromMethod($interaction->installation());
        $query = $this->db->prepare(
            "UPDATE {$this->tables->get('challenges')} SET consumed_at=%s WHERE installation_identity_hash=%s AND installation_epoch=%d AND interaction_id_hash=%s AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>%s",
            Sql::utc($at), $scope->identityHash(), $scope->epoch(), hex2bin($interaction->id()->value()), Sql::utc($at),
        );
        if ($this->sql->execute($query, 'consume interaction') !== 1) {
            throw PersistenceException::compareAndSwapFailed('consume interaction');
        }
    }

    public function revokePendingAuthentication(UserId $userId, InstallationBinding $installation, SessionDigest $session): void
    {
        $scope = InstallationScope::fromMethod($installation);
        $query = $this->db->prepare(
            "UPDATE {$this->tables->get('challenges')} SET revoked_at=UTC_TIMESTAMP() WHERE installation_identity_hash=%s AND installation_epoch=%d AND user_id=%d AND session_token_hash=%s AND purpose='authentication' AND consumed_at IS NULL AND revoked_at IS NULL",
            $scope->identityHash(), $scope->epoch(), $userId->value(), Sql::opaque32($session->value()),
        );
        $this->sql->execute($query, 'revoke pending authentication interactions');
    }

    /** @return array<string,mixed>|null */
    private function row(InteractionId $id, InstallationScope $scope, bool $forUpdate): ?array
    {
        $query = $this->db->prepare(
            "SELECT * FROM {$this->tables->get('challenges')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND interaction_id_hash=%s" . ($forUpdate ? ' FOR UPDATE' : ''),
            $scope->identityHash(), $scope->epoch(), hex2bin($id->value()),
        );

        return $this->sql->row($query, 'read interaction');
    }

    private function hydrate(array $row, InstallationScope $scope, ?Clock $clock): Interaction
    {
        $snapshots = [];
        foreach (Sql::decodeJson((string) ($row['allowed_method_ids'] ?? '[]')) as $item) {
            if (!is_array($item) || !isset($item['id'], $item['provider'], $item['status'], $item['revision'])) {
                throw new PersistenceException('Persisted method snapshot is invalid.');
            }
            $snapshots[] = new MethodSnapshot(
                MethodId::fromString((string) $item['id']),
                UserId::fromInt((int) ($item['user_id'] ?? $row['user_id'])),
                new InstallationBinding(bin2hex($scope->identityHash()), $scope->epoch()),
                ProviderKey::fromString((string) $item['provider']),
                MethodStatus::from((string) $item['status']),
                (int) $item['revision'],
            );
        }
        $id = InteractionId::fromHash(bin2hex((string) $row['interaction_id_hash']));
        $providerState = Sql::decodeJson((string) ($row['provider_state'] ?? ''));
        $referenceValue = $providerState['__pds_interaction_reference'] ?? null;
        $policyValues = $providerState['__pds_policy_snapshot'] ?? [];
        if (!is_string($referenceValue)) {
            throw new PersistenceException('Persisted interaction reference is unavailable.');
        }
        unset($providerState['__pds_interaction_reference']);
        unset($providerState['__pds_policy_snapshot']);
        $reference = InteractionReference::fromString($referenceValue);
        $start = ProviderStart::withoutReference(
            new ProviderPublicPayload([]),
            new ProviderServerState($providerState),
        )->withReference($reference);
        $status = $row['revoked_at'] !== null ? InteractionStatus::REVOKED : ($row['consumed_at'] !== null ? InteractionStatus::CONSUMED : InteractionStatus::OPEN);

        return new Interaction(
            $id,
            $reference,
            UserId::fromInt((int) $row['user_id']),
            new InstallationBinding(bin2hex($scope->identityHash()), $scope->epoch()),
            new SessionDigest(bin2hex((string) $row['session_token_hash'])),
            InteractionPurpose::from((string) $row['purpose']),
            ProviderKey::fromString((string) $row['provider_key']),
            ServerChallenge::fromString(Sql::externalId((string) $row['server_challenge'])),
            $start,
            new MethodSnapshotCollection($snapshots),
            PolicySnapshot::fromArray(is_array($policyValues) ? $policyValues : []),
            new DateTimeImmutable((string) $row['created_at'], new \DateTimeZone('UTC')),
            new DateTimeImmutable((string) $row['expires_at'], new \DateTimeZone('UTC')),
            $status,
        );
    }

    private function scopeOrThrow(): InstallationScope
    {
        if ($this->scope === null) {
            throw new \InvalidArgumentException('Interaction reads require an installation scope.');
        }

        return $this->scope;
    }
}
