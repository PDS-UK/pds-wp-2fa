<?php

declare(strict_types=1);

namespace PDS\WP2FA\Persistence;

use DateInterval;
use DateTimeImmutable;

final class RateLimitRepository
{
    private Sql $sql;

    /** @var array<string,array{limit:int,short:int,medium:int,long:int}> */
    private const THRESHOLDS = [
        'user_provider' => ['limit' => 5, 'short' => 30, 'medium' => 300, 'long' => 3600],
        'user_provider_network' => ['limit' => 10, 'short' => 30, 'medium' => 300, 'long' => 3600],
        'installation_provider' => ['limit' => 100, 'short' => 60, 'medium' => 60, 'long' => 60],
    ];

    public function __construct(private Wpdb $db, private TableNames $tables, private InstallationScope $scope)
    {
        $this->sql = new Sql($db);
    }

    /** @return array{failure_count:int,blocked_until:?DateTimeImmutable} */
    public function recordFailure(string $bucketType, ?int $userId, ?string $providerKey, ?string $networkDigest, DateTimeImmutable $at): array
    {
        if (!isset(self::THRESHOLDS[$bucketType])) {
            throw new \InvalidArgumentException('Unknown rate-limit bucket type.');
        }
        if ($networkDigest !== null && strlen($networkDigest) !== 64 && strlen($networkDigest) !== 32) {
            throw new \InvalidArgumentException('Network identifiers must already be a keyed digest.');
        }
        $windowEnd = $at->add(new DateInterval('PT5M'));
        $canonical = implode('|', [$bucketType, (string) $userId, (string) $providerKey, $networkDigest ?? '']);
        $bucket = hash('sha256', $canonical, true);
        $threshold = self::THRESHOLDS[$bucketType];
        $table = $this->tables->get('rate_limits');
        $query = $this->db->prepare(
            "INSERT INTO {$table} (bucket_key_hash,installation_identity_hash,installation_epoch,bucket_type,user_id,provider_key,method_id,network_key_hash,window_started_at,window_ends_at,failure_count,blocked_until,updated_at) VALUES (%s,%s,%d,%s,%s,%s,NULL,%s,%s,%s,1,NULL,%s) ON DUPLICATE KEY UPDATE failure_count=IF(window_ends_at<=VALUES(window_ends_at),1,failure_count+1), window_started_at=IF(window_ends_at<=VALUES(window_ends_at),VALUES(window_started_at),window_started_at), window_ends_at=IF(window_ends_at<=VALUES(window_ends_at),VALUES(window_ends_at),window_ends_at), blocked_until=CASE WHEN IF(window_ends_at<=VALUES(window_ends_at),1,failure_count+1)>=%d THEN DATE_ADD(%s, INTERVAL %d SECOND) WHEN IF(window_ends_at<=VALUES(window_ends_at),1,failure_count+1)>=%d THEN DATE_ADD(%s, INTERVAL %d SECOND) WHEN IF(window_ends_at<=VALUES(window_ends_at),1,failure_count+1)>=%d THEN DATE_ADD(%s, INTERVAL %d SECOND) ELSE blocked_until END, updated_at=%s",
            $bucket, $this->scope->identityHash(), $this->scope->epoch(), $bucketType, $userId, $providerKey,
            $networkDigest === null ? null : Sql::opaque32($networkDigest), Sql::utc($at), Sql::utc($windowEnd), Sql::utc($at),
            $threshold['long'], Sql::utc($at), $threshold['long'], $threshold['medium'], Sql::utc($at), $threshold['medium'], $threshold['limit'], Sql::utc($at), $threshold['short'], Sql::utc($at),
        );
        $this->sql->execute($query, 'record rate-limit failure');
        $row = $this->sql->row($this->db->prepare("SELECT failure_count,blocked_until FROM {$table} WHERE installation_identity_hash=%s AND installation_epoch=%d AND bucket_key_hash=%s", $this->scope->identityHash(), $this->scope->epoch(), $bucket), 'read rate-limit bucket');
        if ($row === null) {
            throw PersistenceException::queryFailed('read rate-limit bucket', $this->db->get_error());
        }

        return ['failure_count' => (int) $row['failure_count'], 'blocked_until' => Sql::date($row['blocked_until'] ?? null)];
    }

    public function isBlocked(string $bucketType, ?int $userId, ?string $providerKey, ?string $networkDigest, DateTimeImmutable $at): bool
    {
        $canonical = implode('|', [$bucketType, (string) $userId, (string) $providerKey, $networkDigest ?? '']);
        $bucket = hash('sha256', $canonical, true);
        $query = $this->db->prepare("SELECT blocked_until FROM {$this->tables->get('rate_limits')} WHERE installation_identity_hash=%s AND installation_epoch=%d AND bucket_key_hash=%s", $this->scope->identityHash(), $this->scope->epoch(), $bucket);
        $value = $this->db->get_var($query);
        return is_string($value) && $value !== '' && new DateTimeImmutable($value, new \DateTimeZone('UTC')) > $at;
    }
}
