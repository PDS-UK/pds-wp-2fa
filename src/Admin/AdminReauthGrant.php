<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

use DateTimeImmutable;

final class AdminReauthGrant
{
    public function __construct(
        private readonly string $grantIdHash,
        private readonly int $userId,
        private readonly AdminScope $scope,
        private readonly DateTimeImmutable $issuedAt,
        private readonly DateTimeImmutable $expiresAt,
    ) {
        if ($grantIdHash === '' || $userId < 1 || $expiresAt < $issuedAt) {
            throw new \InvalidArgumentException('Invalid administrative re-authentication grant.');
        }
    }

    public function grantIdHash(): string
    {
        return $this->grantIdHash;
    }

    public function userId(): int
    {
        return $this->userId;
    }

    public function scope(): AdminScope
    {
        return $this->scope;
    }

    public function issuedAt(): DateTimeImmutable
    {
        return $this->issuedAt;
    }

    public function expiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }

    /** @return array<string, mixed> */
    public function toPersistenceRecord(): array
    {
        return [
            'grant_id_hash' => $this->grantIdHash,
            'user_id' => $this->userId,
            'scope' => $this->scope->value,
            'issued_at' => $this->issuedAt->format(DATE_ATOM),
            'expires_at' => $this->expiresAt->format(DATE_ATOM),
        ];
    }
}
