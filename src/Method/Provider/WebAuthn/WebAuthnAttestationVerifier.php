<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;

interface WebAuthnAttestationVerifier
{
    public function verify(
        PublicKeyCredential $credential,
        PublicKeyCredentialCreationOptions $options,
        WebAuthnPolicy $policy,
    ): CredentialRecord;
}
