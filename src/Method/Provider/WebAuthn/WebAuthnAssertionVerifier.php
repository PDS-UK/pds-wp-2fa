<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

interface WebAuthnAssertionVerifier
{
    public function verify(
        CredentialRecord $stored,
        PublicKeyCredential $credential,
        PublicKeyCredentialRequestOptions $options,
        ?string $userHandle,
        WebAuthnPolicy $policy,
    ): CredentialRecord;
}
