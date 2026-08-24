<?php

declare(strict_types=1);

namespace PDS\WP2FA\Console;

interface CliOperations
{
    /** @return array<string, mixed> */
    public function status(?string $user = null): array;
    /** @return array<string, mixed> */
    public function settings(): array;
    /** @return list<array<string, mixed>> */
    public function roles(): array;
    /** @return array<string, mixed> */
    public function userStatus(string $user): array;
    /** @return array<string, mixed> */
    public function recoveryStatus(string $user): array;
    /** @param array<string, mixed> $filters @return list<array<string, mixed>> */
    public function auditList(array $filters): array;
    /** @return array<string, mixed> */
    public function identityStatus(): array;
    public function identityGenerate(): string;
    public function identityInit(): void;
    public function identityRebind(): void;
    public function identityRotate(): void;
    public function setEnforcement(bool $enabled, ReasonCode $reason, bool $confirmProduction): void;
    public function setRole(string $role, bool $enabled, ?int $graceSeconds, ReasonCode $reason): void;
    public function extendGrace(string $user, int $seconds, ReasonCode $reason): void;
    public function resetSessions(string $user, ReasonCode $reason): void;
    public function resetEnrollment(string $user, ReasonCode $reason): void;
    public function revokeMethod(string $user, string $method, ReasonCode $reason): void;
    public function revokeRecovery(string $user, ReasonCode $reason): void;
    /** @return array<string, mixed> */
    public function pruneAudit(?string $before, bool $dryRun): array;
}
