<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

final class WebAuthnCredentialRecordCodec
{
    private SerializerInterface $serializer;

    public function __construct(?SerializerInterface $serializer = null)
    {
        $this->serializer = $serializer ?? (new WebauthnSerializerFactory(
            new AttestationStatementSupportManager([new NoneAttestationStatementSupport()]),
        ))->create();
    }

    /** @return array<string, mixed> */
    public function encode(CredentialRecord $record): array
    {
        try {
            $encoded = $this->serializer->normalize($record);
        } catch (\Throwable $exception) {
            throw WebAuthnException::unavailable($exception);
        }
        if (!is_array($encoded)) {
            throw WebAuthnException::unavailable();
        }

        return $encoded;
    }

    /** @param array<string, mixed> $encoded */
    public function decode(array $encoded): CredentialRecord
    {
        try {
            $record = $this->serializer->denormalize($encoded, CredentialRecord::class);
        } catch (\Throwable $exception) {
            throw WebAuthnException::unavailable($exception);
        }
        if (!$record instanceof CredentialRecord) {
            throw WebAuthnException::unavailable();
        }

        return $record;
    }
}
