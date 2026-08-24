<?php

declare(strict_types=1);

namespace PDS\WP2FA\Method;

use DateTimeImmutable;

final class MethodLifecycleService
{
    private const AUTHENTICATION_LIFETIME_SECONDS = 300;
    private const ENROLLMENT_LIFETIME_SECONDS = 600;

    public function __construct(
        private ProviderRegistry $providers,
        private MethodStore $methods,
        private InteractionStore $interactions,
        private SessionStore $sessions,
        private TransactionManager $transactions,
        private Clock $clock,
    ) {
    }

    public function startEnrollment(
        UserId $user,
        InstallationBinding $installation,
        SessionDigest $session,
        ProviderKey $providerKey,
        PolicySnapshot $policy,
    ): ProviderStart {
        $provider = $this->provider($providerKey);
        if (!$provider->capabilities()->supportsEnrollment()) {
            throw new ProviderContractViolation('The selected provider does not support enrollment.');
        }

        $interaction = $this->newInteraction(
            $user,
            $installation,
            $session,
            InteractionPurpose::ENROLLMENT,
            $providerKey,
            $policy,
            new MethodSnapshotCollection([]),
            static function (ProviderContext $context) use ($provider): ProviderStart {
                return $provider->startEnrollment($context);
            },
            self::ENROLLMENT_LIFETIME_SECONDS,
        );

        $this->interactions->create($interaction);

        return $interaction->start();
    }

    public function completeEnrollment(
        InteractionReference $reference,
        UserId $user,
        InstallationBinding $installation,
        SessionDigest $session,
        ProviderKey $providerKey,
        UntrustedInput $input,
    ): MethodRecord {
        $interaction = $this->loadInteraction(
            $reference,
            $user,
            $installation,
            $session,
            InteractionPurpose::ENROLLMENT,
            $providerKey,
        );
        $provider = $this->provider($providerKey);
        $context = $this->contextFor($interaction);
        $result = $provider->completeEnrollment($context, $interaction->start(), $input);
        $draft = $result->draft();

        if (
            !$draft->userId()->equals($user)
            || !$draft->installation()->equals($installation)
            || !$draft->providerKey()->equals($providerKey)
        ) {
            throw new ProviderContractViolation('The provider returned a draft with the wrong binding.');
        }

        return $this->transactions->transaction(function () use ($interaction, $draft): MethodRecord {
            $record = $this->methods->create($draft, $this->clock->now());
            $this->interactions->consume($interaction, $this->clock->now());

            return $record;
        });
    }

    public function startAuthentication(
        UserId $user,
        InstallationBinding $installation,
        SessionDigest $session,
        ProviderKey $providerKey,
        PolicySnapshot $policy,
        MethodId $methodId,
    ): ProviderStart {
        $method = $this->methods->find($user, $installation, $methodId);
        if ($method === null || !$method->isActive() || !$method->providerKey()->equals($providerKey)) {
            throw new InteractionRejected('The requested authentication method is unavailable.');
        }

        $provider = $this->provider($providerKey);
        if (!$provider->capabilities()->supportsAuthentication()) {
            throw new ProviderContractViolation('The selected provider does not support authentication.');
        }

        $this->interactions->revokePendingAuthentication($user, $installation, $session);
        $snapshots = new MethodSnapshotCollection([MethodSnapshot::fromRecord($method)]);
        $interaction = $this->newInteraction(
            $user,
            $installation,
            $session,
            InteractionPurpose::AUTHENTICATION,
            $providerKey,
            $policy,
            $snapshots,
            static function (ProviderContext $context) use ($provider): ProviderStart {
                return $provider->startVerification($context);
            },
            self::AUTHENTICATION_LIFETIME_SECONDS,
        );

        $this->interactions->create($interaction);

        return $interaction->start();
    }

    public function verifyAuthentication(
        InteractionReference $reference,
        UserId $user,
        InstallationBinding $installation,
        SessionDigest $session,
        ProviderKey $providerKey,
        UntrustedInput $input,
    ): VerificationResult {
        $interaction = $this->loadInteraction(
            $reference,
            $user,
            $installation,
            $session,
            InteractionPurpose::AUTHENTICATION,
            $providerKey,
        );
        $provider = $this->provider($providerKey);
        $context = $this->contextFor($interaction);
        $result = $provider->verify($context, $interaction->start(), $input);

        if (!$result->succeeded()) {
            return $result;
        }

        $methodId = $result->methodId();
        if ($methodId === null || !$interaction->methodSnapshot()->contains($methodId)) {
            throw new ProviderContractViolation('The provider returned a method outside the interaction snapshot.');
        }

        return $this->transactions->transaction(function () use ($interaction, $provider, $context, $result, $user, $installation, $methodId): VerificationResult {
            $method = $this->methods->findForUpdate($user, $installation, $methodId);
            if ($method === null || !$method->isActive()) {
                throw new InteractionRejected('The authentication method is no longer available.');
            }

            $snapshot = $interaction->methodSnapshot()->find($methodId);
            if ($snapshot === null || !$snapshot->matchesRecord($method)) {
                throw new InteractionRejected('The authentication method changed during verification.');
            }

            $commit = $provider->commitVerification($context, $result);
            if (!$commit->providerKey()->equals($provider->key())) {
                throw new ProviderContractViolation('The provider returned a commit for another provider.');
            }

            $at = $this->clock->now();
            $this->methods->markAuthenticated($method, $commit, $at);
            $this->interactions->consume($interaction, $at);
            $this->sessions->satisfy($user, $interaction->session());

            return $result;
        });
    }

    private function provider(ProviderKey $key): AuthenticationMethodProvider
    {
        try {
            return $this->providers->get($key);
        } catch (\InvalidArgumentException $exception) {
            throw new InteractionRejected('The selected authentication provider is unavailable.', 0, $exception);
        }
    }

    /**
     * @param callable(ProviderContext): ProviderStart $startProvider
     */
    private function newInteraction(
        UserId $user,
        InstallationBinding $installation,
        SessionDigest $session,
        InteractionPurpose $purpose,
        ProviderKey $providerKey,
        PolicySnapshot $policy,
        MethodSnapshotCollection $snapshots,
        callable $startProvider,
        int $lifetimeSeconds,
    ): Interaction {
        $reference = InteractionReference::random();
        $id = $reference->id();
        $challenge = ServerChallenge::random();
        $createdAt = $this->clock->now();
        $context = new ProviderContext(
            $user,
            $installation,
            $session,
            $id,
            $purpose,
            $providerKey,
            $challenge,
            $policy,
            $snapshots,
            $this->clock,
        );
        $start = $startProvider($context)->withReference($reference);

        return new Interaction(
            $id,
            $reference,
            $user,
            $installation,
            $session,
            $purpose,
            $providerKey,
            $challenge,
            $start,
            $snapshots,
            $policy,
            $createdAt,
            $createdAt->modify('+' . $lifetimeSeconds . ' seconds'),
        );
    }

    private function contextFor(Interaction $interaction): ProviderContext
    {
        return new ProviderContext(
            $interaction->userId(),
            $interaction->installation(),
            $interaction->session(),
            $interaction->id(),
            $interaction->purpose(),
            $interaction->providerKey(),
            $interaction->challenge(),
            $interaction->policy(),
            $interaction->methodSnapshot(),
            $this->clock,
        );
    }

    private function loadInteraction(
        InteractionReference $reference,
        UserId $user,
        InstallationBinding $installation,
        SessionDigest $session,
        InteractionPurpose $purpose,
        ProviderKey $providerKey,
    ): Interaction {
        $interaction = $this->interactions->findForUpdate($reference->id());
        if ($interaction === null) {
            throw new InteractionRejected('The authentication interaction is unavailable.');
        }

        if (
            !$interaction->isOpen()
            || $interaction->isExpired($this->clock->now())
            || !$interaction->userId()->equals($user)
            || !$interaction->installation()->equals($installation)
            || !$interaction->session()->equals($session)
            || $interaction->purpose() !== $purpose
            || !$interaction->providerKey()->equals($providerKey)
        ) {
            throw new InteractionRejected('The authentication interaction is invalid.');
        }

        return $interaction;
    }
}
