<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

final class LibraryWebAuthnAssertionVerifier implements WebAuthnAssertionVerifier
{
    public function verify(
        CredentialRecord $stored,
        PublicKeyCredential $credential,
        PublicKeyCredentialRequestOptions $options,
        ?string $userHandle,
        WebAuthnPolicy $policy,
    ): CredentialRecord {
        if (!$credential->response instanceof AuthenticatorAssertionResponse) {
            throw WebAuthnException::invalidInput();
        }

        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($policy->allowedOrigins(), false);

        try {
            return (new AuthenticatorAssertionResponseValidator($factory->requestCeremony()))->check(
                $stored,
                $credential->response,
                $options,
                $policy->rpId(),
                $userHandle,
            );
        } catch (\Throwable $exception) {
            throw WebAuthnException::invalidInput($exception);
        }
    }
}
