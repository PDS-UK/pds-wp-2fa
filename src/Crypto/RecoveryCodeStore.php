<?php

declare(strict_types=1);

namespace PDS\WP2FA\Crypto;

interface RecoveryCodeStore
{
    /**
     * Return only currently unused records for the expected generation.
     *
     * @return iterable<int, RecoveryCodeRecord>
     */
    public function unused(string $generationId): iterable;

    /**
     * Atomically mark a code used only when it is still unused.
     *
     * A false result represents a concurrent use or replay and must never be
     * treated as a successful authentication.
     */
    public function consumeIfUnused(string $codeId): bool;
}
