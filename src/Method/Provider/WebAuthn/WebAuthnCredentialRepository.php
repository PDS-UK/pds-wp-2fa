<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use DateTimeImmutable;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\MethodRecord;
use PDS\WP2FA\Method\RevocationReason;
use PDS\WP2FA\Method\UserId;
use Webauthn\CredentialRecord;

interface WebAuthnCredentialRepository
{
    /** @return list<WebAuthnCredential> */
    public function activeFor(UserId $user, InstallationBinding $installation): array;

    public function userHandleFor(UserId $user, InstallationBinding $installation): ?string;

    public function findActiveByCredentialId(
        UserId $user,
        InstallationBinding $installation,
        string $credentialId,
    ): ?WebAuthnCredential;

    public function findByCredentialId(
        InstallationBinding $installation,
        string $credentialId,
    ): ?WebAuthnCredential;

    /** Persist the updated library record with an optimistic/CAS guard. */
    public function persistVerification(
        WebAuthnCredential $current,
        CredentialRecord $updated,
        DateTimeImmutable $at,
    ): void;

    /** Revocation is idempotent and must not delete the credential record. */
    public function revoke(
        MethodRecord $method,
        RevocationReason $reason,
        DateTimeImmutable $at,
    ): void;
}
