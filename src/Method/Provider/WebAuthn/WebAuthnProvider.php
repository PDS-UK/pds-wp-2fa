<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method\Provider\WebAuthn;

use DateTimeImmutable;
use PDS\WP2FA\Method\AuthenticationMethodProvider;
use PDS\WP2FA\Method\EnrollmentResult;
use PDS\WP2FA\Method\FriendlyLabel;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\InteractionPurpose;
use PDS\WP2FA\Method\MethodDraft;
use PDS\WP2FA\Method\MethodRecord;
use PDS\WP2FA\Method\MethodSnapshot;
use PDS\WP2FA\Method\ProviderCapabilities;
use PDS\WP2FA\Method\ProviderContext;
use PDS\WP2FA\Method\ProviderContractViolation;
use PDS\WP2FA\Method\ProviderData;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\ProviderPublicPayload;
use PDS\WP2FA\Method\ProviderServerState;
use PDS\WP2FA\Method\ProviderStart;
use PDS\WP2FA\Method\RevocationReason;
use PDS\WP2FA\Method\SafeMetadata;
use PDS\WP2FA\Method\UntrustedInput;
use PDS\WP2FA\Method\UserId;
use PDS\WP2FA\Method\VerificationCommit;
use PDS\WP2FA\Method\VerificationFailureReason;
use PDS\WP2FA\Method\VerificationResult;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

final class WebAuthnProvider implements AuthenticationMethodProvider
{
    private const SCHEMA_VERSION = 1;
    private const DEFAULT_LABEL = 'Security key';

    private ProviderKey $key;
    private WebAuthnResponseDecoder $decoder;
    private WebAuthnAttestationVerifier $attestationVerifier;
    private WebAuthnAssertionVerifier $assertionVerifier;
    private WebAuthnCredentialRecordCodec $recordCodec;

    public function __construct(
        private WebAuthnPolicy $policy,
        private WebAuthnCredentialRepository $credentials,
        ?WebAuthnResponseDecoder $decoder = null,
        ?WebAuthnAttestationVerifier $attestationVerifier = null,
        ?WebAuthnAssertionVerifier $assertionVerifier = null,
        ?WebAuthnCredentialRecordCodec $recordCodec = null,
    ) {
        $this->key = ProviderKey::fromString('webauthn');
        $this->decoder = $decoder ?? new LibraryWebAuthnResponseDecoder();
        $this->attestationVerifier = $attestationVerifier ?? new LibraryWebAuthnAttestationVerifier();
        $this->assertionVerifier = $assertionVerifier ?? new LibraryWebAuthnAssertionVerifier();
        $this->recordCodec = $recordCodec ?? new WebAuthnCredentialRecordCodec();
    }

    public function key(): ProviderKey
    {
        return $this->key;
    }

    public function capabilities(): ProviderCapabilities
    {
        return new ProviderCapabilities(
            supportsEnrollment: true,
            supportsAuthentication: true,
            supportsRotation: true,
            supportsDiscovery: true,
            supportsMultipleActiveMethods: true,
            sensitivePublicPayload: true,
        );
    }

    public function startEnrollment(ProviderContext $context): ProviderStart
    {
        $this->policy->assertEnabled();
        $this->assertPurpose($context, [InteractionPurpose::ENROLLMENT, InteractionPurpose::ROTATION]);

        $active = $this->activeForContext($context);
        $userHandle = $this->credentials->userHandleFor($context->userId(), $context->installation());
        if ($userHandle === null && $active !== []) {
            $userHandle = $active[0]->record()->userHandle;
        }
        $userHandle ??= random_bytes(32);
        $this->assertUserHandle($userHandle);

        $excludeCredentials = [];
        foreach ($active as $credential) {
            $excludeCredentials[] = $credential->record()->getPublicKeyCredentialDescriptor();
        }
        $options = $this->creationOptions($context, $userHandle, $excludeCredentials);
        $excluded = array_map(
            fn (PublicKeyCredentialDescriptor $descriptor): array => [
                'id' => Base64Url::encode($descriptor->id),
                'transports' => array_values($descriptor->transports),
            ],
            $excludeCredentials,
        );

        return ProviderStart::withoutReference(
            new ProviderPublicPayload($this->serializeCreationOptions($options)),
            WebAuthnInteractionBinding::forContext($context, $context->purpose()->value, [
                'user_handle' => Base64Url::encode($userHandle),
                'excluded_credentials' => $excluded,
            ]),
        );
    }

    public function completeEnrollment(
        ProviderContext $context,
        ProviderStart $start,
        UntrustedInput $input,
    ): EnrollmentResult {
        $this->policy->assertEnabled();
        WebAuthnInteractionBinding::assertMatches($context, $start, $context->purpose()->value);
        $payload = $input->asArray();
        $credentialInput = $this->credentialInput($payload);

        try {
            $credential = $this->decoder->decode($credentialInput);
            $credential->type === PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY
                || throw WebAuthnException::invalidInput();
            $credential->response instanceof AuthenticatorAttestationResponse
                || throw WebAuthnException::invalidInput();

            $state = $start->serverState()->toArray();
            $userHandle = Base64Url::decode($this->stateString($state, 'user_handle'));
            $options = $this->creationOptions($context, $userHandle, $this->excludedFromState($state));
            $record = $this->attestationVerifier->verify($credential, $options, $this->policy);

            hash_equals($record->publicKeyCredentialId, $credential->rawId)
                || throw WebAuthnException::invalidInput();
            hash_equals($record->userHandle, $userHandle)
                || throw WebAuthnException::invalidInput();
            $record->uvInitialized === true || throw WebAuthnException::invalidInput();
            $this->credentials->findByCredentialId($context->installation(), $record->publicKeyCredentialId) === null
                || throw WebAuthnException::invalidInput();

            $label = $this->labelFromPayload($payload);
            $draft = new MethodDraft(
                $context->userId(),
                $context->installation(),
                $this->key,
                self::SCHEMA_VERSION,
                $label,
                new ProviderData(self::SCHEMA_VERSION, [
                    'credential_record' => $this->recordCodec->encode($record),
                    'rp_id' => $this->policy->rpId(),
                    'user_handle' => Base64Url::encode($record->userHandle),
                ]),
            );

            return new EnrollmentResult($draft, $this->metadataFor($record));
        } catch (WebAuthnException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw WebAuthnException::invalidInput($exception);
        }
    }

    public function startVerification(ProviderContext $context): ProviderStart
    {
        $this->policy->assertEnabled();
        $this->assertPurpose($context, [InteractionPurpose::AUTHENTICATION]);

        $snapshots = $context->methodSnapshot()->all();
        $allowedMethodIds = [];
        foreach ($snapshots as $snapshot) {
            if ($snapshot->status()->value === 'active') {
                $allowedMethodIds[$snapshot->methodId()->value()] = true;
            }
        }

        $credentials = $this->activeForContext($context);
        $descriptors = [];
        foreach ($credentials as $credential) {
            if ($allowedMethodIds !== [] && !isset($allowedMethodIds[$credential->methodId()->value()])) {
                continue;
            }
            $descriptors[] = $credential->record()->getPublicKeyCredentialDescriptor();
        }
        if ($descriptors === []) {
            throw WebAuthnException::unavailable();
        }

        $options = $this->requestOptions($context, $descriptors);
        $credentialState = array_map(
            fn (PublicKeyCredentialDescriptor $descriptor): array => [
                'id' => Base64Url::encode($descriptor->id),
                'transports' => array_values($descriptor->transports),
            ],
            $descriptors,
        );

        return ProviderStart::withoutReference(
            new ProviderPublicPayload($this->serializeRequestOptions($options)),
            WebAuthnInteractionBinding::forContext($context, InteractionPurpose::AUTHENTICATION->value, [
                'credentials' => $credentialState,
            ]),
        );
    }

    public function verify(
        ProviderContext $context,
        ProviderStart $start,
        UntrustedInput $input,
    ): \PDS\WP2FA\Method\VerificationResult {
        try {
            $this->policy->assertEnabled();
            WebAuthnInteractionBinding::assertMatches($context, $start, InteractionPurpose::AUTHENTICATION->value);
            $payload = $input->asArray();
            $credential = $this->decoder->decode($this->credentialInput($payload));
            if ($credential->type !== PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY
                || !$credential->response instanceof AuthenticatorAssertionResponse) {
                return VerificationResult::failure(VerificationFailureReason::MALFORMED_INPUT);
            }

            $state = $start->serverState()->toArray();
            $submittedId = Base64Url::encode($credential->rawId);
            if (!$this->stateContainsCredential($state, $submittedId)) {
                return VerificationResult::failure(VerificationFailureReason::INVALID_PROOF);
            }
            $stored = $this->credentials->findActiveByCredentialId(
                $context->userId(),
                $context->installation(),
                $credential->rawId,
            );
            if ($stored === null || !$context->methodSnapshot()->contains($stored->methodId())) {
                return VerificationResult::failure(VerificationFailureReason::INVALID_PROOF);
            }

            $descriptors = $this->descriptorsFromState($state, 'credentials');
            $options = $this->requestOptions($context, $descriptors);
            $updated = $this->assertionVerifier->verify(
                $stored->record(),
                $credential,
                $options,
                $stored->record()->userHandle,
                $this->policy,
            );
            hash_equals($updated->publicKeyCredentialId, $stored->record()->publicKeyCredentialId)
                || throw WebAuthnException::invalidInput();
            hash_equals($updated->userHandle, $stored->record()->userHandle)
                || throw WebAuthnException::invalidInput();
            $updated->uvInitialized === true || throw WebAuthnException::invalidInput();

            $commit = new WebAuthnVerificationCommit($this->key, $stored, $updated);
            return VerificationResult::success($stored->methodId(), $commit, $this->metadataFor($updated));
        } catch (WebAuthnException $exception) {
            return VerificationResult::failure(VerificationFailureReason::INVALID_PROOF);
        } catch (\Throwable) {
            return VerificationResult::failure(VerificationFailureReason::INVALID_PROOF);
        }
    }

    public function commitVerification(
        ProviderContext $context,
        \PDS\WP2FA\Method\VerificationResult $result,
    ): VerificationCommit {
        if (!$result->succeeded() || !$result->commit() instanceof WebAuthnVerificationCommit) {
            throw new ProviderContractViolation('The WebAuthn result cannot be committed.');
        }
        /** @var WebAuthnVerificationCommit $commit */
        $commit = $result->commit();
        $this->credentials->persistVerification(
            $commit->current(),
            $commit->updated(),
            $context->clock()->now(),
        );

        return $commit;
    }

    public function revoke(
        ProviderContext $context,
        MethodRecord $method,
        RevocationReason $reason,
    ): void {
        $this->credentials->revoke($method, $reason, $context->clock()->now());
    }

    /** @return list<WebAuthnCredential> */
    private function activeForContext(ProviderContext $context): array
    {
        $credentials = $this->credentials->activeFor($context->userId(), $context->installation());
        foreach ($credentials as $credential) {
            if (!$credential instanceof WebAuthnCredential
                || !$credential->userId()->equals($context->userId())
                || !$credential->installation()->equals($context->installation())) {
                throw WebAuthnException::unavailable();
            }
        }

        return array_values($credentials);
    }

    private function creationOptions(
        ProviderContext $context,
        string $userHandle,
        array $excludeCredentials,
    ): PublicKeyCredentialCreationOptions {
        return new PublicKeyCredentialCreationOptions(
            PublicKeyCredentialRpEntity::create($this->policy->relyingPartyName(), $this->policy->rpId()),
            PublicKeyCredentialUserEntity::create(
                'wp-user-' . $context->userId()->value(),
                $userHandle,
                'WordPress user',
            ),
            $context->challenge()->value(),
            array_map(
                static fn (int $algorithm): PublicKeyCredentialParameters => PublicKeyCredentialParameters::createPk($algorithm),
                $this->policy->algorithms(),
            ),
            AuthenticatorSelectionCriteria::create(
                null,
                $this->policy->userVerificationRequirement(),
                $this->policy->residentKeyRequirement(),
            ),
            $this->policy->attestationConveyance(),
            $excludeCredentials,
            $this->policy->timeoutMilliseconds(),
        );
    }

    /** @param list<PublicKeyCredentialDescriptor> $descriptors */
    private function requestOptions(ProviderContext $context, array $descriptors): PublicKeyCredentialRequestOptions
    {
        return new PublicKeyCredentialRequestOptions(
            $context->challenge()->value(),
            $this->policy->rpId(),
            $descriptors,
            $this->policy->userVerificationRequirement(),
            $this->policy->timeoutMilliseconds(),
        );
    }

    /** @return array<string, mixed> */
    private function serializeCreationOptions(PublicKeyCredentialCreationOptions $options): array
    {
        return [
            'challenge' => Base64Url::encode($options->challenge),
            'rp' => ['name' => $options->rp->name, 'id' => $options->rp->id],
            'user' => [
                'name' => $options->user->name,
                'displayName' => $options->user->displayName,
                'id' => Base64Url::encode($options->user->id),
            ],
            'pubKeyCredParams' => array_map(
                static fn (PublicKeyCredentialParameters $parameter): array => [
                    'type' => $parameter->type,
                    'alg' => $parameter->alg,
                ],
                $options->pubKeyCredParams,
            ),
            'authenticatorSelection' => [
                'userVerification' => $options->authenticatorSelection?->userVerification,
                'residentKey' => $options->authenticatorSelection?->residentKey,
                'requireResidentKey' => true,
            ],
            'attestation' => $options->attestation,
            'excludeCredentials' => array_map($this->serializeDescriptor(...), $options->excludeCredentials),
            'timeout' => $options->timeout,
        ];
    }

    /** @return array<string, mixed> */
    private function serializeRequestOptions(PublicKeyCredentialRequestOptions $options): array
    {
        return [
            'challenge' => Base64Url::encode($options->challenge),
            'rpId' => $options->rpId,
            'allowCredentials' => array_map($this->serializeDescriptor(...), $options->allowCredentials),
            'userVerification' => $options->userVerification,
            'timeout' => $options->timeout,
        ];
    }

    /** @return array<string, mixed> */
    private function serializeDescriptor(PublicKeyCredentialDescriptor $descriptor): array
    {
        return [
            'type' => $descriptor->type,
            'id' => Base64Url::encode($descriptor->id),
            'transports' => array_values($descriptor->transports),
        ];
    }

    /** @param array<string, mixed> $payload @return array<string, mixed> */
    private function credentialInput(array $payload): array
    {
        $credential = $payload['credential'] ?? $payload;
        if (!is_array($credential)) {
            throw WebAuthnException::invalidInput();
        }

        return $credential;
    }

    private function labelFromPayload(array $payload): FriendlyLabel
    {
        $label = $payload['label'] ?? self::DEFAULT_LABEL;
        if (!is_string($label)) {
            throw WebAuthnException::invalidInput();
        }
        try {
            return FriendlyLabel::fromString($label);
        } catch (\Throwable $exception) {
            throw WebAuthnException::invalidInput($exception);
        }
    }

    private function assertPurpose(ProviderContext $context, array $purposes): void
    {
        if (!in_array($context->purpose(), $purposes, true)) {
            throw new ProviderContractViolation('The WebAuthn operation is not valid for this interaction.');
        }
    }

    private function assertUserHandle(string $userHandle): void
    {
        if ($userHandle === '' || strlen($userHandle) > 64) {
            throw WebAuthnException::unavailable();
        }
    }

    /** @param array<string, mixed> $state */
    private function stateString(array $state, string $key): string
    {
        if (!isset($state[$key]) || !is_string($state[$key]) || $state[$key] === '') {
            throw WebAuthnException::invalidInput();
        }

        return $state[$key];
    }

    /** @param array<string, mixed> $state @return list<PublicKeyCredentialDescriptor> */
    private function excludedFromState(array $state): array
    {
        return $this->descriptorsFromState($state, 'excluded_credentials');
    }

    /** @param array<string, mixed> $state @return list<PublicKeyCredentialDescriptor> */
    private function descriptorsFromState(array $state, string $key): array
    {
        if (!isset($state[$key]) || !is_array($state[$key])) {
            throw WebAuthnException::invalidInput();
        }
        $descriptors = [];
        foreach ($state[$key] as $descriptor) {
            if (!is_array($descriptor) || !isset($descriptor['id']) || !is_string($descriptor['id'])) {
                throw WebAuthnException::invalidInput();
            }
            $transports = $descriptor['transports'] ?? [];
            if (!is_array($transports)) {
                throw WebAuthnException::invalidInput();
            }
            $transports = array_values(array_filter(
                $transports,
                static fn (mixed $transport): bool => is_string($transport)
                    && in_array($transport, PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORTS, true),
            ));
            $descriptors[] = PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                Base64Url::decode($descriptor['id']),
                $transports,
            );
        }

        return $descriptors;
    }

    /** @param array<string, mixed> $state */
    private function stateContainsCredential(array $state, string $credentialId): bool
    {
        foreach ($this->descriptorsFromState($state, 'credentials') as $descriptor) {
            if (hash_equals($descriptor->id, Base64Url::decode($credentialId))) {
                return true;
            }
        }

        return false;
    }

    private function metadataFor(\Webauthn\CredentialRecord $record): SafeMetadata
    {
        return SafeMetadata::fromArray([
            'provider' => 'webauthn',
            'user_verified' => $record->uvInitialized === true,
            'backup_eligible' => $record->backupEligible,
            'backup_status' => $record->backupStatus,
            'counter' => $record->counter,
        ]);
    }
}
