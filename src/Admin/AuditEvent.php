<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

use DateTimeImmutable;

final class AuditEvent
{
    private function __construct(
        private readonly string $eventType,
        private readonly string $severity,
        private readonly AdminActor $actor,
        private readonly ?int $targetUserId,
        private readonly ?string $roleKey,
        private readonly ?string $methodId,
        private readonly string $installationFingerprint,
        private readonly int $installationEpoch,
        private readonly string $outcome,
        private readonly ReasonCode $reason,
        private readonly SafeMetadata $metadata,
        private readonly DateTimeImmutable $occurredAt,
        private readonly string $correlationIdHash,
    ) {
        if ($installationEpoch < 1 || !in_array($severity, ['info', 'warning', 'high'], true)) {
            throw new \InvalidArgumentException('Invalid audit event binding or severity.');
        }
        if (!in_array($outcome, ['success', 'failure'], true)) {
            throw new \InvalidArgumentException('Invalid audit event outcome.');
        }
        if ($targetUserId !== null && $targetUserId < 1) {
            throw new \InvalidArgumentException('Audit target user IDs must be positive.');
        }
    }

    /** @param array<string, mixed> $metadata */
    public static function create(
        string $eventType,
        string $severity,
        AdminActor $actor,
        ?int $targetUserId,
        ?string $roleKey,
        ?string $methodId,
        string $installationFingerprint,
        int $installationEpoch,
        string $outcome,
        ReasonCode $reason,
        array $metadata,
        DateTimeImmutable $occurredAt,
        ?string $correlationId = null,
    ): self {
        if ($roleKey !== null && preg_match('/^[a-z][a-z0-9_-]{0,63}$/', $roleKey) !== 1) {
            throw new AdminException('Audit role keys must be stable identifiers.', 'unsafe_metadata');
        }
        if ($methodId !== null && preg_match('/^[A-Za-z0-9_-]{1,128}$/', $methodId) !== 1) {
            throw new AdminException('Audit method references must be opaque identifiers.', 'unsafe_metadata');
        }
        if ($installationFingerprint === '' || strlen($installationFingerprint) > 64) {
            throw new AdminException('Audit installation binding is unavailable.', 'unsafe_metadata');
        }

        $correlationHash = $correlationId === null
            ? ''
            : 'sha256:' . substr(hash('sha256', $correlationId), 0, 12) . '...';

        return new self(
            $eventType,
            $severity,
            $actor,
            $targetUserId,
            $roleKey,
            $methodId,
            $installationFingerprint,
            $installationEpoch,
            $outcome,
            $reason,
            SafeMetadata::forEvent($eventType, $metadata),
            $occurredAt,
            $correlationHash,
        );
    }

    public function eventType(): string { return $this->eventType; }
    public function severity(): string { return $this->severity; }
    public function actor(): AdminActor { return $this->actor; }
    public function targetUserId(): ?int { return $this->targetUserId; }

    /** @return array<string, mixed> */
    public function toSafeArray(): array
    {
        return [
            'event_type' => $this->eventType,
            'severity' => $this->severity,
            'occurred_at' => $this->occurredAt->format(DATE_ATOM),
            'actor_kind' => $this->actor->kind(),
            'actor_user_id' => $this->actor->userId(),
            'source' => $this->actor->source(),
            'target_user_id' => $this->targetUserId,
            'role_key' => $this->roleKey,
            'method_id' => $this->methodId,
            'installation_fingerprint' => $this->installationFingerprint,
            'installation_epoch' => $this->installationEpoch,
            'outcome' => $this->outcome,
            'reason_code' => $this->reason->value,
            'safe_metadata' => $this->metadata->toArray(),
            'schema_version' => 1,
            'correlation_id_hash' => $this->correlationIdHash === '' ? null : $this->correlationIdHash,
        ];
    }
}
