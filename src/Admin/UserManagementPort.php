<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface UserManagementPort
{
    public function extendGrace(int $userId, int $seconds, ReasonCode $reason): void;

    public function resetSessions(int $userId, ReasonCode $reason): void;

    public function revokeMethod(int $userId, string $methodId, ReasonCode $reason): void;

    public function revokeRecovery(int $userId, ReasonCode $reason): void;

    public function resetEnrollment(int $userId, ReasonCode $reason): void;
}
