<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

use DateTimeImmutable;

interface InteractionStore
{
    public function create(Interaction $interaction): void;

    public function find(InteractionId $id): ?Interaction;

    /** This lookup must lock the row until the surrounding transaction ends. */
    public function findForUpdate(InteractionId $id): ?Interaction;

    /** Implementations must compare-and-set open -> consumed. */
    public function consume(Interaction $interaction, DateTimeImmutable $at): void;

    /** Starting a new authentication invalidates older bearer references for this session. */
    public function revokePendingAuthentication(
        UserId $userId,
        InstallationBinding $installation,
        SessionDigest $session,
    ): void;
}
