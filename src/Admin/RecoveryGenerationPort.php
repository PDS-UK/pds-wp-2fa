<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

interface RecoveryGenerationPort
{
    public function regenerateForUser(int $userId): RecoveryGenerationResult;
}
