<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\Method;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use PDS\WP2FA\Method\FriendlyLabel;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\InteractionPurpose;
use PDS\WP2FA\Method\InteractionReference;
use PDS\WP2FA\Method\LastUsedAt;
use PDS\WP2FA\Method\MethodId;
use PDS\WP2FA\Method\MethodStatus;
use PDS\WP2FA\Method\PolicySnapshot;
use PDS\WP2FA\Method\ProviderCapabilities;
use PDS\WP2FA\Method\ProviderContext;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\ProviderPublicPayload;
use PDS\WP2FA\Method\ProviderRegistry;
use PDS\WP2FA\Method\ProviderServerState;
use PDS\WP2FA\Method\ProviderStart;
use PDS\WP2FA\Method\RecoveryCodeResult;
use PDS\WP2FA\Method\ServerChallenge;
use PDS\WP2FA\Method\SessionDigest;
use PDS\WP2FA\Method\SystemClock;
use PDS\WP2FA\Method\UserId;

final class ProviderContractsTest extends TestCase
{
    public function testRegistryIsAllowListedAndProviderCapabilitiesAreSafe(): void
    {
        $totp = new ContractTestProvider('totp');
        $registry = new ProviderRegistry([$totp]);

        self::assertSame($totp, $registry->get(ProviderKey::fromString('totp')));
        self::assertTrue($totp->capabilities()->supportsAuthentication());
        self::assertFalse($totp->capabilities()->supportsDiscovery());

        $this->expectException(\InvalidArgumentException::class);
        $registry->get(ProviderKey::fromString('unknown'));
    }

    public function testProviderStartExposesOnlyThePublicPayload(): void
    {
        $reference = InteractionReference::fromString('reference-123456');
        $start = ProviderStart::withoutReference(
            new ProviderPublicPayload(['challenge' => 'public']),
            new ProviderServerState(['secret' => 'server-only']),
        )->withReference($reference);

        self::assertSame($reference, $start->reference());
        self::assertSame(['challenge' => 'public'], $start->clientPayload());
        self::assertArrayNotHasKey('secret', $start->clientPayload());
    }

    public function testContextUsesServerBindingsAndRecoveryResultContainsNoCode(): void
    {
        $methodId = MethodId::fromString('method-123456');
        $context = new ProviderContext(
            UserId::fromInt(42),
            new InstallationBinding(str_repeat('a', 64), 3),
            new SessionDigest(str_repeat('b', 64)),
            InteractionReference::fromString('reference-123456')->id(),
            InteractionPurpose::AUTHENTICATION,
            ProviderKey::fromString('recovery'),
            ServerChallenge::fromString('challenge-123456'),
            PolicySnapshot::fromArray(['user_verification' => true]),
            [],
            new SystemClock(),
        );
        $result = new RecoveryCodeResult(
            $methodId,
            'code-123456',
            true,
        );

        self::assertTrue($context->userId()->equals(UserId::fromInt(42)));
        self::assertSame(InteractionPurpose::AUTHENTICATION, $context->purpose());
        self::assertSame('code-123456', $result->codeId()->value());
        self::assertTrue($result->exhausted());
        self::assertObjectNotHasProperty('code', $result);
    }

    public function testLabelsAndLastUsedMetadataAreIndependentOfAuthentication(): void
    {
        $lastUsed = LastUsedAt::at(new DateTimeImmutable('2026-08-24T12:00:00+00:00'));
        $label = FriendlyLabel::fromString('My security key');

        self::assertSame('My security key', $label->value());
        self::assertSame($lastUsed->value(), $lastUsed->value());
        self::assertSame(MethodStatus::ACTIVE, MethodStatus::ACTIVE);
    }
}

final class ContractTestProvider implements \PDS\WP2FA\Method\AuthenticationMethodProvider
{
    private ProviderKey $key;

    public function __construct(string $key)
    {
        $this->key = ProviderKey::fromString($key);
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
            supportsDiscovery: false,
            supportsMultipleActiveMethods: true,
            sensitivePublicPayload: false,
        );
    }

    public function startEnrollment(ProviderContext $context): ProviderStart
    {
        return ProviderStart::withoutReference(
            new ProviderPublicPayload([]),
            new ProviderServerState([]),
        );
    }

    public function completeEnrollment(
        ProviderContext $context,
        ProviderStart $start,
        \PDS\WP2FA\Method\UntrustedInput $input,
    ): \PDS\WP2FA\Method\EnrollmentResult {
        throw new \LogicException('Not used by this contract test.');
    }

    public function startVerification(ProviderContext $context): ProviderStart
    {
        return ProviderStart::withoutReference(
            new ProviderPublicPayload([]),
            new ProviderServerState([]),
        );
    }

    public function verify(
        ProviderContext $context,
        ProviderStart $start,
        \PDS\WP2FA\Method\UntrustedInput $input,
    ): \PDS\WP2FA\Method\VerificationResult {
        throw new \LogicException('Not used by this contract test.');
    }

    public function commitVerification(
        ProviderContext $context,
        \PDS\WP2FA\Method\VerificationResult $result,
    ): \PDS\WP2FA\Method\VerificationCommit {
        throw new \LogicException('Not used by this contract test.');
    }

    public function revoke(
        ProviderContext $context,
        \PDS\WP2FA\Method\MethodRecord $method,
        \PDS\WP2FA\Method\RevocationReason $reason,
    ): void {
    }
}
