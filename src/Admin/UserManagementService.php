<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

final class UserManagementService
{
    public function __construct(
        private readonly UserManagementPort $port,
        private readonly AuditService $audit,
        private readonly AdminTransaction $transaction,
    ) {
    }

    public function extendGrace(AdminActor $actor, int $userId, int $seconds, ReasonCode $reason): void
    {
        self::assertUser($userId);
        self::assertRange($seconds, 1, 31536000, 'Extension seconds');
        $this->transaction->run(function () use ($actor, $userId, $seconds, $reason): void {
            $this->port->extendGrace($userId, $seconds, $reason);
            $this->audit->record('grace_extension_granted', 'info', $actor, $reason, [
                'target_user_id' => $userId,
                'extension_seconds' => $seconds,
                'previous_deadline' => null,
                'new_deadline' => null,
            ], targetUserId: $userId);
        });
    }

    public function resetSessions(AdminActor $actor, int $userId, ReasonCode $reason): void
    {
        self::assertUser($userId);
        $this->transaction->run(function () use ($actor, $userId, $reason): void {
            $this->port->resetSessions($userId, $reason);
            $this->audit->record('admin_sessions_reset', 'warning', $actor, $reason, [
                'target_user_id' => $userId,
            ], targetUserId: $userId);
        });
    }

    public function revokeMethod(AdminActor $actor, int $userId, string $methodId, ReasonCode $reason): void
    {
        self::assertUser($userId);
        self::assertOpaqueReference($methodId, 'Method');
        $this->transaction->run(function () use ($actor, $userId, $methodId, $reason): void {
            $this->port->revokeMethod($userId, $methodId, $reason);
            $this->audit->record('method_revoked', 'warning', $actor, $reason, [
                'target_user_id' => $userId,
            ], targetUserId: $userId, methodId: $methodId);
        });
    }

    public function revokeRecovery(AdminActor $actor, int $userId, ReasonCode $reason): void
    {
        self::assertUser($userId);
        $this->transaction->run(function () use ($actor, $userId, $reason): void {
            $this->port->revokeRecovery($userId, $reason);
            $this->audit->record('recovery_generation_revoked', 'warning', $actor, $reason, [
                'target_user_id' => $userId,
            ], targetUserId: $userId);
        });
    }

    public function resetEnrollment(
        AdminActor $actor,
        int $userId,
        ReasonCode $reason,
        bool $confirmProduction = false,
        string $environment = 'production',
    ): void {
        self::assertUser($userId);
        if ($environment === 'production' && !$confirmProduction) {
            throw new AdminException('Production enrollment reset requires explicit confirmation.', 'confirmation_required');
        }
        $this->transaction->run(function () use ($actor, $userId, $reason): void {
            $this->port->resetEnrollment($userId, $reason);
            $this->audit->record('admin_enrollment_reset', 'high', $actor, $reason, [
                'target_user_id' => $userId,
                'old_method_count' => 0,
                'new_state' => 'enrollment_required',
            ], targetUserId: $userId);
        });
    }

    private static function assertUser(int $userId): void
    {
        if ($userId < 1) {
            throw new AdminException('The target user was not found.', 'target_not_found');
        }
    }

    private static function assertRange(int $value, int $min, int $max, string $name): void
    {
        if ($value < $min || $value > $max) {
            throw new AdminException($name . ' is outside its allowed range.', 'validation_error');
        }
    }

    private static function assertOpaqueReference(string $value, string $name): void
    {
        if (preg_match('/^[A-Za-z0-9_-]{1,128}$/', $value) !== 1) {
            throw new AdminException($name . ' reference is invalid.', 'validation_error');
        }
    }
}
