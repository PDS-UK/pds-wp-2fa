<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Integration;

require_once __DIR__ . '/Fixtures.php';

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use PDS\WP2FA\Admin\AdminActor;
use PDS\WP2FA\Admin\AuditEvent;
use PDS\WP2FA\Admin\ReasonCode;
use PDS\WP2FA\Crypto\RecoveryCodeHasher;
use PDS\WP2FA\Crypto\RecoveryCodeRecord;
use PDS\WP2FA\Crypto\RecoveryCodeVerifier;
use PDS\WP2FA\Crypto\Totp;
use PDS\WP2FA\Crypto\TotpProfile;
use PDS\WP2FA\Http\AuthenticationSnapshot;
use PDS\WP2FA\Http\GateResponseAdapter;
use PDS\WP2FA\Http\RateLimitDecision;
use PDS\WP2FA\Http\Route;
use PDS\WP2FA\Http\RouteGate;
use PDS\WP2FA\Identity\ConfigurationSources;
use PDS\WP2FA\Identity\EnvironmentType;
use PDS\WP2FA\Identity\IdentityBindingState;
use PDS\WP2FA\Identity\IdentityConfigurationResolver;
use PDS\WP2FA\Identity\IdentityFingerprint;
use PDS\WP2FA\Identity\InstallationIdentity;
use PDS\WP2FA\Identity\InstallationIdentityRuntime;
use PDS\WP2FA\Method\FinalMethodGuard;
use PDS\WP2FA\Method\FinalMethodProtectionException;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\InteractionRejected;
use PDS\WP2FA\Method\MethodLifecycleService;
use PDS\WP2FA\Method\PolicySnapshot;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\ProviderRegistry;
use PDS\WP2FA\Method\SessionDigest;
use PDS\WP2FA\Method\SessionState;
use PDS\WP2FA\Method\UntrustedInput;
use PDS\WP2FA\Method\UserId;
use PDS\WP2FA\Method\ProviderContext;
use PDS\WP2FA\Method\InteractionPurpose;
use PDS\WP2FA\Method\InteractionId;
use PDS\WP2FA\Method\ServerChallenge;
use PDS\WP2FA\Method\MethodSnapshotCollection;
use PDS\WP2FA\Method\ProviderStart;
use PDS\WP2FA\Method\ProviderPublicPayload;
use PDS\WP2FA\Method\ProviderServerState;
use PDS\WP2FA\Method\ProviderData;
use PDS\WP2FA\Method\SafeMetadata as MethodSafeMetadata;
use PDS\WP2FA\Method\MethodId;
use PDS\WP2FA\Method\ProviderCapabilities;
use PDS\WP2FA\Method\ProviderCommit;
use PDS\WP2FA\Method\VerificationResult;
use PDS\WP2FA\Method\FriendlyLabel;
use PDS\WP2FA\Method\MethodDraft;
use PDS\WP2FA\Method\EnrollmentResult;
use PDS\WP2FA\Method\VerificationFailureReason;
use PDS\WP2FA\Method\AuthenticationMethodProvider;
use PDS\WP2FA\Policy\EnrollmentCycleId;
use PDS\WP2FA\Policy\RoleKey;
use PDS\WP2FA\Policy\RolePolicy;
use PDS\WP2FA\Policy\RolePolicyLifecycle;
use PDS\WP2FA\Policy\RolePolicyResolver;
use PDS\WP2FA\Policy\RolePolicyResolutionInput;
use PDS\WP2FA\Policy\UserRolePolicyAnchor;
use PDS\WP2FA\WordPress\CallableRequestSignals;
use PDS\WP2FA\WordPress\GateDecision;
use PDS\WP2FA\WordPress\RequestClassifier;
use PDS\WP2FA\WordPress\RequestContext;
use PDS\WP2FA\WordPress\RequestType;
use PDS\WP2FA\WordPress\SafeRedirectTarget;
use PDS\WP2FA\WordPress\SessionTokenDigest;
use PDS\WP2FA\Method\Provider\WebAuthn\WebAuthnException;
use PDS\WP2FA\Method\Provider\WebAuthn\WebAuthnInteractionBinding;
use PDS\WP2FA\Method\Provider\WebAuthn\WebAuthnPolicy;

final class SecurityAcceptanceTest extends TestCase
{
    public function testIdentityMismatchAndMissingBindingFailClosedWithRedactedDiagnostics(): void
    {
        $raw = str_repeat('a', 64);
        $runtime = new InstallationIdentityRuntime(
            new IdentityConfigurationResolver(),
            new IdentityReaderFixture(null),
        );

        $uninitialized = $runtime->inspect(ConfigurationSources::constant($raw), EnvironmentType::PRODUCTION);

        self::assertSame(IdentityBindingState::UNINITIALIZED, $uninitialized->status());
        self::assertSame(503, $uninitialized->httpStatus());
        self::assertSame('pds_wp_2fa_unavailable', $uninitialized->publicErrorCode());
        self::assertStringNotContainsString($raw, json_encode($uninitialized->diagnostics(), JSON_THROW_ON_ERROR));

        $foreign = InstallationIdentity::fromCanonicalHex(str_repeat('b', 64));
        $runtime = new InstallationIdentityRuntime(
            new IdentityConfigurationResolver(),
            new IdentityReaderFixture(new \PDS\WP2FA\Identity\InstallationBinding(
                $foreign->fingerprint(),
                4,
                EnvironmentType::production(),
            )),
        );
        $mismatch = $runtime->inspect(ConfigurationSources::constant($raw), EnvironmentType::PRODUCTION);

        self::assertSame(IdentityBindingState::IDENTITY_MISMATCH, $mismatch->status());
        self::assertFalse($mismatch->allowsSecurityState());
        self::assertSame(503, $mismatch->httpStatus());
    }

    public function testEnrollmentModeRedirectsToEnrollmentThenActiveMethodRequiresCurrentSessionChallenge(): void
    {
        $user = UserId::fromInt(42);
        $session = new SessionDigest('session-one');
        $installation = new InstallationBinding('installation-one', 1);
        $gate = new RouteGate(
            new \PDS\WP2FA\Http\CallableAuthenticationContextProvider(fn (): AuthenticationSnapshot => new AuthenticationSnapshot(
                $user,
                $session,
                $installation,
                SessionState::PENDING,
                AuthenticationSnapshot::MODE_ENROLLMENT_REQUIRED,
                true,
                true,
                true,
                false,
            )),
            new FixtureUrls(),
        );

        $enrollment = $gate->decide(new RequestContext(RequestType::ORDINARY_ADMIN, '/wp-admin/', null, null));

        self::assertSame(GateDecision::REDIRECT, $enrollment->outcome());
        self::assertStringContainsString('route=enroll', (string) $enrollment->target());

        $challengeGate = new RouteGate(
            new \PDS\WP2FA\Http\CallableAuthenticationContextProvider(fn (): AuthenticationSnapshot => new AuthenticationSnapshot(
                $user,
                $session,
                $installation,
                SessionState::PENDING,
                AuthenticationSnapshot::MODE_CHALLENGE,
                true,
                true,
                true,
                true,
            )),
            new FixtureUrls(),
        );
        $challenge = $challengeGate->decide(new RequestContext(RequestType::ORDINARY_ADMIN, '/wp-admin/', null, null));

        self::assertSame(GateDecision::REDIRECT, $challenge->outcome());
        self::assertStringContainsString('route=challenge', (string) $challenge->target());
    }

    public function testMethodLifecycleBindsAuthenticationToOneSessionAndDoesNotSatisfyOnEnrollment(): void
    {
        $clock = new FrozenMethodClock(new DateTimeImmutable('2026-08-24T12:00:00+00:00'));
        $methods = new FixtureMethodStore();
        $interactions = new FixtureInteractionStore();
        $sessions = new FixtureSessionStore();
        $service = new MethodLifecycleService(
            new ProviderRegistry([new FixtureProvider()]),
            $methods,
            $interactions,
            $sessions,
            new FixtureTransactionManager(),
            $clock,
        );
        $user = UserId::fromInt(42);
        $installation = new InstallationBinding('installation-one', 1);
        $sessionOne = new SessionDigest('session-one');
        $sessionTwo = new SessionDigest('session-two');
        $provider = ProviderKey::fromString('totp');
        $policy = PolicySnapshot::fromArray(['mode' => 'challenge']);

        $enrollment = $service->startEnrollment($user, $installation, $sessionOne, $provider, $policy);
        $method = $service->completeEnrollment(
            $enrollment->reference(),
            $user,
            $installation,
            $sessionOne,
            $provider,
            new UntrustedInput(['secret' => 'never-persisted-in-test']),
        );

        self::assertSame(SessionState::PENDING, $sessions->state($user, $sessionOne));
        self::assertTrue($method->isActive());

        $authentication = $service->startAuthentication(
            $user,
            $installation,
            $sessionOne,
            $provider,
            $policy,
            $method->methodId(),
        );

        $this->expectException(InteractionRejected::class);
        $service->verifyAuthentication(
            $authentication->reference(),
            $user,
            $installation,
            $sessionTwo,
            $provider,
            new UntrustedInput(['proof' => 'valid']),
        );
    }

    public function testWinningSessionOnlyIsSatisfiedAfterTheBoundChallengeSucceeds(): void
    {
        $clock = new FrozenMethodClock(new DateTimeImmutable('2026-08-24T12:00:00+00:00'));
        $methods = new FixtureMethodStore();
        $interactions = new FixtureInteractionStore();
        $sessions = new FixtureSessionStore();
        $service = new MethodLifecycleService(
            new ProviderRegistry([new FixtureProvider()]),
            $methods,
            $interactions,
            $sessions,
            new FixtureTransactionManager(),
            $clock,
        );
        $user = UserId::fromInt(42);
        $installation = new InstallationBinding('installation-one', 1);
        $sessionOne = new SessionDigest('session-one');
        $sessionTwo = new SessionDigest('session-two');
        $provider = ProviderKey::fromString('totp');
        $policy = PolicySnapshot::fromArray(['mode' => 'challenge']);
        $enrollment = $service->startEnrollment($user, $installation, $sessionOne, $provider, $policy);
        $method = $service->completeEnrollment(
            $enrollment->reference(),
            $user,
            $installation,
            $sessionOne,
            $provider,
            new UntrustedInput([]),
        );
        $authentication = $service->startAuthentication(
            $user,
            $installation,
            $sessionOne,
            $provider,
            $policy,
            $method->methodId(),
        );

        $result = $service->verifyAuthentication(
            $authentication->reference(),
            $user,
            $installation,
            $sessionOne,
            $provider,
            new UntrustedInput(['proof' => 'valid']),
        );

        self::assertTrue($result->isSuccessful());
        self::assertSame(SessionState::SATISFIED, $sessions->state($user, $sessionOne));
        self::assertSame(SessionState::PENDING, $sessions->state($user, $sessionTwo));
        self::assertSame(1, $methods->authenticated);
    }

    public function testStrictestRoleDeadlineWinsAndEnforcementStartsAtTheDeadline(): void
    {
        $at = new DateTimeImmutable('2026-08-24T12:00:00+00:00');
        $lifecycle = new RolePolicyLifecycle();
        $editor = $lifecycle->enable(
            RolePolicy::discovered(new RoleKey('editor'), 'Editor', $at),
            $at,
        )->policy();
        $editor = $lifecycle->setGracePeriod($editor, 86400, $at)->policy();
        $reviewer = $lifecycle->enable(
            RolePolicy::discovered(new RoleKey('reviewer'), 'Reviewer', $at),
            $at,
        )->policy();
        $reviewer = $lifecycle->setGracePeriod($reviewer, 3600, $at)->policy();

        $before = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
            42,
            [new RoleKey('editor'), new RoleKey('reviewer')],
            [$editor, $reviewer],
            [],
            false,
            new EnrollmentCycleId('cycle-one'),
            [],
            $at->modify('+3599 seconds'),
        ));
        $atDeadline = (new RolePolicyResolver())->resolve(new RolePolicyResolutionInput(
            42,
            [new RoleKey('editor'), new RoleKey('reviewer')],
            [$editor, $reviewer],
            [],
            false,
            new EnrollmentCycleId('cycle-one'),
            [],
            $at->modify('+3600 seconds'),
        ));

        self::assertTrue($before->isProtected());
        self::assertFalse($before->isOverdue());
        self::assertSame($at->modify('+3600 seconds')->getTimestamp(), $before->effectiveDeadline()?->getTimestamp());
        self::assertTrue($atDeadline->isOverdue());
        self::assertSame($at->modify('+3600 seconds')->getTimestamp(), $atDeadline->effectiveDeadline()?->getTimestamp());
    }

    public function testTotpAdjacentWindowAndReplayAreDeterministic(): void
    {
        $clock = new FrozenUnixClock(90);
        $totp = new Totp($clock, new TotpProfile(window: 1));
        $secret = '12345678901234567890';
        $previous = $totp->generate($secret, 60);
        $outside = $totp->generate($secret, 150);

        self::assertTrue($totp->verify($previous, $secret)->isValid());
        self::assertFalse($totp->verify($outside, $secret)->isValid());
        self::assertSame('already_accepted', $totp->verify($previous, $secret, lastAcceptedStep: 2)->reason());
    }

    public function testRecoveryCodeIsConsumedExactlyOnceAndConcurrentLossIsRejected(): void
    {
        $hasher = new RecoveryCodeHasher();
        $code = 'AB12CD34EF567890123456789ABCDEF0';
        $store = new InMemoryRecoveryStoreFixture([
            new RecoveryCodeRecord('recovery-one', $hasher->hash($code)),
        ]);
        $verifier = new RecoveryCodeVerifier($hasher);

        self::assertTrue($verifier->verifyAndConsume($code, 'generation-one', $store)->isSuccessful());
        self::assertSame('not_found', $verifier->verifyAndConsume($code, 'generation-one', $store)->reason());

        $race = new InMemoryRecoveryStoreFixture([
            new RecoveryCodeRecord('recovery-two', $hasher->hash($code)),
        ], false);
        self::assertSame('already_used', $verifier->verifyAndConsume($code, 'generation-one', $race)->reason());
    }

    public function testWebAuthnFixtureBindsChallengeToInteractionSessionAndInstallation(): void
    {
        $clock = new FrozenMethodClock(new DateTimeImmutable('2026-08-24T12:00:00+00:00'));
        $reference = \PDS\WP2FA\Method\InteractionReference::fromString('reference-one');
        $context = new ProviderContext(
            UserId::fromInt(42),
            new InstallationBinding('installation-one', 7),
            new SessionDigest('session-one'),
            $reference->id(),
            InteractionPurpose::AUTHENTICATION,
            ProviderKey::fromString('webauthn'),
            ServerChallenge::fromString('challenge-one'),
            PolicySnapshot::fromArray(['uv' => 'required']),
            new MethodSnapshotCollection([]),
            $clock,
        );
        $start = ProviderStart::withoutReference(
            new ProviderPublicPayload(['challenge' => 'challenge-one']),
            WebAuthnInteractionBinding::forContext($context, 'assertion'),
        )->withReference($reference);

        WebAuthnInteractionBinding::assertMatches($context, $start, 'assertion');

        $wrongSession = new ProviderContext(
            UserId::fromInt(42),
            new InstallationBinding('installation-one', 7),
            new SessionDigest('session-two'),
            $reference->id(),
            InteractionPurpose::AUTHENTICATION,
            ProviderKey::fromString('webauthn'),
            ServerChallenge::fromString('challenge-one'),
            PolicySnapshot::fromArray(['uv' => 'required']),
            new MethodSnapshotCollection([]),
            $clock,
        );

        $this->expectException(WebAuthnException::class);
        WebAuthnInteractionBinding::assertMatches($wrongSession, $start, 'assertion');
    }

    public function testWebAuthnPolicyIsProductionOnlyAndOriginBound(): void
    {
        $policy = new WebAuthnPolicy('example.com', ['https://example.com']);

        self::assertTrue($policy->isAllowedOrigin('https://example.com/'));
        self::assertFalse($policy->isAllowedOrigin('https://evil.example.com'));
        self::assertSame('required', $policy->userVerificationRequirement());
        self::assertSame('required', $policy->residentKeyRequirement());

        $disabled = new WebAuthnPolicy('example.com', ['https://example.com'], enabled: false);
        $this->expectException(WebAuthnException::class);
        $disabled->assertEnabled();
    }

    public function testRateLimitThresholdsSurviveSessionChangesAndWindowExpiry(): void
    {
        $limiter = new ThresholdRateLimiterFixture();
        $installation = new InstallationBinding('installation-one', 1);
        $first = $this->snapshot(new SessionDigest('session-one'), $installation);
        $second = $this->snapshot(new SessionDigest('session-two'), $installation);

        for ($i = 0; $i < 4; ++$i) {
            $limiter->recordFailure('totp', $first);
        }
        self::assertTrue($limiter->check('totp', $first)->allowed());
        $limiter->recordFailure('totp', $first);
        self::assertSame(30, $limiter->check('totp', $second)->retryAfter());

        for ($i = 0; $i < 5; ++$i) {
            $limiter->recordFailure('totp', $second);
        }
        self::assertSame(300, $limiter->check('totp', $first)->retryAfter());

        for ($i = 0; $i < 10; ++$i) {
            $limiter->recordFailure('totp', $first);
        }
        self::assertSame(3600, $limiter->check('totp', $second)->retryAfter());

        $limiter->advanceWindow();
        self::assertTrue($limiter->check('totp', $first)->allowed());
    }

    public function testFinalMethodProtectionRequiresReplacementOrSessionSuccess(): void
    {
        $guard = new FinalMethodGuard();

        $this->expectException(FinalMethodProtectionException::class);
        $guard->assertManualRevocationAllowed(\PDS\WP2FA\Method\MethodStatus::ACTIVE, new \PDS\WP2FA\Method\RetainedMethodCount(1));
    }

    public function testFinalMethodReplacementAndRecoveryRulesAreExplicit(): void
    {
        $guard = new FinalMethodGuard();

        $guard->assertManualRevocationAllowed(\PDS\WP2FA\Method\MethodStatus::ACTIVE, new \PDS\WP2FA\Method\RetainedMethodCount(2));
        $guard->assertReplacementAllowed(new \PDS\WP2FA\Method\RetainedMethodCount(1), true);
        self::assertTrue($guard->allowsRecoveryExhaustion(true));
        self::assertFalse($guard->allowsRecoveryExhaustion(false));

        $this->expectException(FinalMethodProtectionException::class);
        $guard->assertReplacementAllowed(new \PDS\WP2FA\Method\RetainedMethodCount(1), false);
    }

    public function testRouteBoundaryBlocksHandlersAndPreservesNonInteractiveRequests(): void
    {
        $snapshot = $this->snapshot(new SessionDigest('session-one'), new InstallationBinding('installation-one', 1));
        $gate = new RouteGate(
            new \PDS\WP2FA\Http\CallableAuthenticationContextProvider(fn (): AuthenticationSnapshot => $snapshot),
            new FixtureUrls(),
        );
        $adapter = new GateResponseAdapter();

        $ordinary = new RequestContext(RequestType::ORDINARY_ADMIN, '/wp-admin/index.php', null, null);
        $ordinaryDecision = $gate->decide($ordinary);
        $handlerRan = false;
        if ($ordinaryDecision->outcome() === GateDecision::ALLOW) {
            $handlerRan = true;
        }
        self::assertFalse($handlerRan);
        self::assertSame(302, $adapter->response($ordinary, $ordinaryDecision)->status());

        $ajax = new RequestContext(RequestType::AJAX, '/wp-admin/admin-ajax.php', 'unrelated_action', null);
        $ajaxResponse = $adapter->response($ajax, $gate->decide($ajax));
        self::assertSame(403, $ajaxResponse->status());
        self::assertStringContainsString('pds_wp_2fa_pending', $ajaxResponse->body());

        $rest = new RequestContext(RequestType::REST_COOKIE, '/wp-json/wp/v2/users', null, null);
        $restResponse = $adapter->response($rest, $gate->decide($rest));
        self::assertSame(403, $restResponse->status());
        self::assertStringContainsString('application/json', $restResponse->headers()['Content-Type']);

        foreach ([RequestType::REST_APPLICATION_PASSWORD, RequestType::REST_NON_COOKIE, RequestType::XML_RPC, RequestType::WP_CLI, RequestType::CRON, RequestType::FRONTEND] as $type) {
            self::assertSame(GateDecision::BYPASS, $gate->decide(new RequestContext($type, '/', null, null))->outcome());
        }
    }

    public function testRequestClassifierSeparatesApplicationPasswordCookieRestAndAdminPost(): void
    {
        self::assertSame(RequestType::ADMIN_POST, $this->classify(['isAdmin' => true, 'requestUri' => '/wp-admin/admin-post.php'])->type());
        self::assertSame(RequestType::AJAX, $this->classify(['isAdmin' => true, 'isAjax' => true, 'requestUri' => '/wp-admin/admin-ajax.php'])->type());
        self::assertSame(RequestType::REST_APPLICATION_PASSWORD, $this->classify(['isRest' => true, 'hasApplicationPassword' => true])->type());
        self::assertSame(RequestType::REST_COOKIE, $this->classify(['isRest' => true, 'isCookie' => true])->type());
        self::assertSame(RequestType::REST_NON_COOKIE, $this->classify(['isRest' => true])->type());
        self::assertSame(RequestType::WP_CLI, $this->classify(['isWpCli' => true])->type());
        self::assertSame(RequestType::CRON, $this->classify(['isCron' => true])->type());
        self::assertSame(RequestType::XML_RPC, $this->classify(['isXmlRpc' => true])->type());
        self::assertSame(RequestType::FRONTEND, $this->classify([])->type());
    }

    public function testSessionTokenDigestIsOpaqueAndDifferentTokensDoNotShareBinding(): void
    {
        $digest = new SessionTokenDigest(fn (): string => 'auth-salt');
        $one = $digest->digest('wordpress-session-one');
        $two = $digest->digest('wordpress-session-two');

        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $one);
        self::assertNotSame($one, $two);
        self::assertStringNotContainsString('wordpress-session-one', $one);
    }

    public function testSafeRedirectsStayWithinAdminAndRejectSecrets(): void
    {
        $redirect = new SafeRedirectTarget(
            static fn (string $candidate, string $fallback): string => $candidate !== '' ? $candidate : $fallback,
            static fn (): string => 'https://example.com/wp-admin/',
        );

        self::assertSame('/wp-admin/edit.php', $redirect->validate('/wp-admin/edit.php'));
        self::assertSame('https://example.com/wp-admin/', $redirect->validate('https://evil.example/wp-admin/'));
        self::assertSame('https://example.com/wp-admin/', $redirect->validate('/wp-admin/?secret=raw'));
        self::assertSame('https://example.com/wp-admin/', $redirect->validate('/wp-admin/../wp-login.php'));
    }

    public function testAuditOutputContainsSafeMetadataButNoRawCredentialOrCorrelation(): void
    {
        $rawCorrelation = 'raw-session-token-and-webauthn-response';
        $event = AuditEvent::create(
            'identity_status_mismatch',
            'high',
            AdminActor::system(),
            42,
            null,
            null,
            'sha256:abcdef123456...',
            7,
            'failure',
            ReasonCode::CLONE_REBIND,
            ['status' => 'identity_mismatch', 'environment_type' => 'production'],
            new DateTimeImmutable('2026-08-24T12:00:00+00:00'),
            $rawCorrelation,
        );
        $encoded = json_encode($event->toSafeArray(), JSON_THROW_ON_ERROR);

        self::assertStringContainsString('identity_status_mismatch', $encoded);
        self::assertStringContainsString('sha256:', $encoded);
        self::assertStringNotContainsString($rawCorrelation, $encoded);
        self::assertStringNotContainsString('recovery-code', $encoded);
        self::assertStringNotContainsString('webauthn-response', $encoded);

        $this->expectException(\PDS\WP2FA\Admin\AdminException::class);
        \PDS\WP2FA\Admin\SafeMetadata::forEvent('identity_status_mismatch', ['secret' => 'raw']);
    }

    public function testFullBrowserWebAuthnCeremonyIsExplicitlyDeferred(): void
    {
        $this->markTestSkipped('A real browser/authenticator ceremony is outside the no-WordPress fixture suite; challenge binding is tested above.');
    }

    private function snapshot(SessionDigest $session, InstallationBinding $installation): AuthenticationSnapshot
    {
        return new AuthenticationSnapshot(
            UserId::fromInt(42),
            $session,
            $installation,
            SessionState::PENDING,
            AuthenticationSnapshot::MODE_CHALLENGE,
            true,
            true,
            true,
            true,
            true,
        );
    }

    /** @param array<string, bool|string> $overrides */
    private function classify(array $overrides): \PDS\WP2FA\WordPress\RequestContext
    {
        $values = array_merge([
            'isAdmin' => false,
            'isAjax' => false,
            'isRest' => false,
            'hasApplicationPassword' => false,
            'isCookie' => false,
            'isXmlRpc' => false,
            'isWpCli' => false,
            'isCron' => false,
            'requestUri' => '/',
        ], $overrides);

        return (new RequestClassifier(new CallableRequestSignals(
            static fn (): bool => (bool) $values['isAdmin'],
            static fn (): bool => (bool) $values['isAjax'],
            static fn (): bool => (bool) $values['isRest'],
            static fn (): bool => (bool) $values['hasApplicationPassword'],
            static fn (): bool => (bool) $values['isCookie'],
            static fn (): bool => (bool) $values['isXmlRpc'],
            static fn (): bool => (bool) $values['isWpCli'],
            static fn (): bool => (bool) $values['isCron'],
            static fn (): string => (string) $values['requestUri'],
            static fn (string $name): ?string => null,
        )))->classify();
    }
}
