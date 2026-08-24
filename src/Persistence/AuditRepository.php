<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use DateInterval;
use DateTimeImmutable;

final class AuditRepository
{
    private Sql $sql;

    public function __construct(private Wpdb $db, private TableNames $tables, private InstallationScope $scope, private int $retentionDays = 400)
    {
        if ($retentionDays < 400 || $retentionDays > 2555) {
            throw new \InvalidArgumentException('Audit retention must be between 400 and 2555 days.');
        }
        $this->sql = new Sql($db);
    }

    /** @param array<string,scalar|null> $metadata */
    public function append(array $event, DateTimeImmutable $at): string
    {
        $metadata = $event['safe_metadata'] ?? [];
        if (!is_array($metadata)) {
            throw new \InvalidArgumentException('Audit metadata must be an allow-listed scalar map.');
        }
        foreach ($metadata as $key => $value) {
            if (!is_string($key) || preg_match('/\A[a-z][a-z0-9_.-]*\z/', $key) !== 1 || preg_match('/password|secret|code|token|challenge|private|credential|response|key/i', $key) === 1 || (is_string($value) && strlen($value) > 256) || ($value !== null && !is_scalar($value))) {
                throw new \InvalidArgumentException('Audit metadata contains a forbidden field.');
            }
        }
        $eventId = (string) ($event['event_id'] ?? Sql::externalId(random_bytes(16)));
        $retained = $at->add(new DateInterval('P' . $this->retentionDays . 'D'));
        $query = $this->db->prepare(
            "INSERT INTO {$this->tables->get('audit_events')} (event_id,installation_identity_hash,installation_epoch,event_type,severity,actor_kind,actor_user_id,subject_user_id,role_key,method_id,source,outcome,reason_code,safe_metadata,schema_version,correlation_id_hash,created_at,retained_until) VALUES (%s,%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,%s)",
            Sql::opaque16($eventId), $this->scope->identityHash(), $this->scope->epoch(), (string) ($event['event_type'] ?? 'unknown'), (string) ($event['severity'] ?? 'info'), (string) ($event['actor_kind'] ?? 'system'), $event['actor_user_id'] ?? null, $event['subject_user_id'] ?? null, $event['role_key'] ?? null, isset($event['method_id']) ? Sql::opaque16((string) $event['method_id']) : null, (string) ($event['source'] ?? 'system'), (string) ($event['outcome'] ?? 'success'), $event['reason_code'] ?? null, Sql::json($metadata), isset($event['correlation_id']) ? Sql::opaque32((string) $event['correlation_id']) : null, Sql::utc($at), Sql::utc($retained),
        );
        $this->sql->execute($query, 'append audit event');
        return $eventId;
    }

    public function purge(DateTimeImmutable $before): int
    {
        $query = $this->db->prepare("DELETE FROM {$this->tables->get('audit_events')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND retained_until<%s", $this->scope->identityHash(), $this->scope->epoch(), Sql::utc($before));
        return $this->sql->execute($query, 'purge audit events');
    }
}
