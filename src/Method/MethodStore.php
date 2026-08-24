<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

use DateTimeImmutable;

interface MethodStore
{
    public function create(MethodDraft $draft, DateTimeImmutable $at): MethodRecord;

    public function find(UserId $userId, InstallationBinding $installation, MethodId $methodId): ?MethodRecord;

    public function findForUpdate(UserId $userId, InstallationBinding $installation, MethodId $methodId): ?MethodRecord;

    /** @return list<MethodRecord> */
    public function activeFor(UserId $userId, InstallationBinding $installation, ProviderKey $provider): array;

    public function markAuthenticated(MethodRecord $method, VerificationCommit $commit, DateTimeImmutable $at): void;

    public function retainedCount(UserId $userId, InstallationBinding $installation): int;

    public function revoke(MethodRecord $method, Revocation $revocation): void;

    public function replace(
        MethodRecord $old,
        MethodDraft $replacement,
        Revocation $revocation,
        DateTimeImmutable $at,
    ): MethodRecord;
}
