<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class AuditService
{
    public function __construct(
        private readonly AuditWriter $writer,
        private readonly Clock $clock,
        private readonly string $installationFingerprint,
        private readonly int $installationEpoch,
    ) {
        if ($installationEpoch < 1) {
            throw new \InvalidArgumentException('The audit installation epoch must be positive.');
        }
    }

    /** @param array<string, mixed> $metadata */
    public function record(
        string $eventType,
        string $severity,
        AdminActor $actor,
        ReasonCode $reason,
        array $metadata = [],
        ?int $targetUserId = null,
        ?string $roleKey = null,
        ?string $methodId = null,
        string $outcome = 'success',
        ?string $correlationId = null,
    ): AuditEvent {
        $event = AuditEvent::create(
            $eventType,
            $severity,
            $actor,
            $targetUserId,
            $roleKey,
            $methodId,
            $this->installationFingerprint,
            $this->installationEpoch,
            $outcome,
            $reason,
            $metadata,
            $this->clock->now(),
            $correlationId,
        );
        $this->writer->append($event);

        return $event;
    }
}
