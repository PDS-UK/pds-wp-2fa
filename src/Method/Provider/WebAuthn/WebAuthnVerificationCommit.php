<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\VerificationCommit;
use Webauthn\CredentialRecord;

final class WebAuthnVerificationCommit implements VerificationCommit
{
    public function __construct(
        private ProviderKey $provider,
        private WebAuthnCredential $current,
        private CredentialRecord $updated,
    ) {
    }

    public function providerKey(): ProviderKey
    {
        return $this->provider;
    }

    public function current(): WebAuthnCredential
    {
        return $this->current;
    }

    public function updated(): CredentialRecord
    {
        return $this->updated;
    }
}
