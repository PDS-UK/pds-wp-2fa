<?php

declare(strict_types=1);

namespace PDS\WP2FA\Admin;

use DateInterval;

final class AdminActionGuard
{
    public function __construct(
        private readonly AdminAuthorizer $authorizer,
        private readonly NonceVerifier $nonceVerifier,
        private readonly PasswordReauthenticator $reauthenticator,
        private readonly ReauthGrantStore $grants,
        private readonly Clock $clock,
    ) {
    }

    public function authorize(
        AdminActor $actor,
        string $capability,
        AdminScope $scope,
        string $nonceAction,
        string $nonce,
        string $password,
        ?int $targetUserId = null,
    ): AdminReauthGrant {
        if ($actor->kind() !== 'user' || $actor->userId() === null) {
            throw new AdminException('Administrative web actions require a user session.', 'authorization_denied');
        }

        $this->authorizer->assertSatisfiedSession($actor);
        $this->authorizer->assertCapability($actor, $capability);
        if ($targetUserId !== null) {
            $this->authorizer->assertCanEditUser($actor, $targetUserId);
        }

        $this->nonceVerifier->assertValid($nonceAction, $nonce);
        $this->reauthenticator->assertValid($actor, $password);

        $issuedAt = $this->clock->now();
        $grant = new AdminReauthGrant(
            hash('sha256', random_bytes(32)),
            $actor->userId(),
            $scope,
            $issuedAt,
            $issuedAt->add(new DateInterval('PT600S')),
        );
        $this->grants->issue($grant);

        return $grant;
    }
}
