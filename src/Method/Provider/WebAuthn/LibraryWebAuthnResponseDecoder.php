<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;

final class LibraryWebAuthnResponseDecoder implements WebAuthnResponseDecoder
{
    private SerializerInterface $serializer;

    public function __construct(?SerializerInterface $serializer = null)
    {
        $this->serializer = $serializer ?? (new WebauthnSerializerFactory(
            new AttestationStatementSupportManager([new NoneAttestationStatementSupport()]),
        ))->create();
    }

    /** @param array<string, mixed> $input */
    public function decode(array $input): PublicKeyCredential
    {
        if (!isset($input['id'], $input['rawId'], $input['type'], $input['response'])
            || !is_string($input['id']) || !is_string($input['rawId']) || !is_string($input['type'])
            || !is_array($input['response'])) {
            throw WebAuthnException::invalidInput();
        }

        try {
            $credential = $this->serializer->denormalize($input, PublicKeyCredential::class);
        } catch (\Throwable $exception) {
            throw WebAuthnException::invalidInput($exception);
        }
        if (!$credential instanceof PublicKeyCredential) {
            throw WebAuthnException::invalidInput();
        }

        return $credential;
    }
}
