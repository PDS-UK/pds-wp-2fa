<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

use DateTimeImmutable;

final class Interaction
{
    public function __construct(
        private InteractionId $id,
        private InteractionReference $reference,
        private UserId $userId,
        private InstallationBinding $installation,
        private SessionDigest $session,
        private InteractionPurpose $purpose,
        private ProviderKey $providerKey,
        private ServerChallenge $challenge,
        private ProviderStart $start,
        private MethodSnapshotCollection $methodSnapshot,
        private PolicySnapshot $policy,
        private DateTimeImmutable $createdAt,
        private DateTimeImmutable $expiresAt,
        private InteractionStatus $status = InteractionStatus::OPEN,
    ) {
        if (!$this->start->hasReference() || !$this->start->reference()->id()->equals($id)) {
            throw new \InvalidArgumentException('An interaction start must carry its interaction reference.');
        }

        if ($expiresAt <= $createdAt) {
            throw new \InvalidArgumentException('An interaction must expire after it is created.');
        }
    }

    public function id(): InteractionId
    {
        return $this->id;
    }

    public function reference(): InteractionReference
    {
        return $this->reference;
    }

    public function userId(): UserId
    {
        return $this->userId;
    }

    public function installation(): InstallationBinding
    {
        return $this->installation;
    }

    public function session(): SessionDigest
    {
        return $this->session;
    }

    public function purpose(): InteractionPurpose
    {
        return $this->purpose;
    }

    public function providerKey(): ProviderKey
    {
        return $this->providerKey;
    }

    public function challenge(): ServerChallenge
    {
        return $this->challenge;
    }

    public function start(): ProviderStart
    {
        return $this->start;
    }

    public function methodSnapshot(): MethodSnapshotCollection
    {
        return $this->methodSnapshot;
    }

    public function policy(): PolicySnapshot
    {
        return $this->policy;
    }

    public function createdAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function expiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function status(): InteractionStatus
    {
        return $this->status;
    }

    public function isOpen(): bool
    {
        return $this->status === InteractionStatus::OPEN;
    }

    public function isExpired(DateTimeImmutable $at): bool
    {
        return $at >= $this->expiresAt;
    }
}
