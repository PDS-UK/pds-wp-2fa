<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;

final class LibraryWebAuthnAttestationVerifier implements WebAuthnAttestationVerifier
{
    public function verify(
        PublicKeyCredential $credential,
        PublicKeyCredentialCreationOptions $options,
        WebAuthnPolicy $policy,
    ): CredentialRecord {
        if (!$credential->response instanceof AuthenticatorAttestationResponse) {
            throw WebAuthnException::invalidInput();
        }

        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($policy->allowedOrigins(), false);

        try {
            return (new AuthenticatorAttestationResponseValidator($factory->creationCeremony()))->check(
                $credential->response,
                $options,
                $policy->rpId(),
            );
        } catch (\Throwable $exception) {
            throw WebAuthnException::invalidInput($exception);
        }
    }
}
