<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\Method;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use PDS\WP2FA\Method\AuthenticationMethodProvider;
use PDS\WP2FA\Method\Clock;
use PDS\WP2FA\Method\EnrollmentResult;
use PDS\WP2FA\Method\FriendlyLabel;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\Interaction;
use PDS\WP2FA\Method\InteractionId;
use PDS\WP2FA\Method\InteractionPurpose;
use PDS\WP2FA\Method\InteractionReference;
use PDS\WP2FA\Method\InteractionStore;
use PDS\WP2FA\Method\MethodDraft;
use PDS\WP2FA\Method\MethodId;
use PDS\WP2FA\Method\MethodRecord;
use PDS\WP2FA\Method\MethodSnapshot;
use PDS\WP2FA\Method\MethodStatus;
use PDS\WP2FA\Method\MethodStore;
use PDS\WP2FA\Method\PolicySnapshot;
use PDS\WP2FA\Method\ProviderCapabilities;
use PDS\WP2FA\Method\ProviderContext;
use PDS\WP2FA\Method\ProviderData;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\ProviderPublicPayload;
use PDS\WP2FA\Method\ProviderRegistry;
use PDS\WP2FA\Method\ProviderServerState;
use PDS\WP2FA\Method\ProviderStart;
use PDS\WP2FA\Method\SafeMetadata;
use PDS\WP2FA\Method\ServerChallenge;
use PDS\WP2FA\Method\SessionDigest;
use PDS\WP2FA\Method\SessionState;
use PDS\WP2FA\Method\SessionStore;
use PDS\WP2FA\Method\SystemClock;
use PDS\WP2FA\Method\TransactionManager;
use PDS\WP2FA\Method\UntrustedInput;
use PDS\WP2FA\Method\UserId;
use PDS\WP2FA\Method\VerificationCommit;
use PDS\WP2FA\Method\VerificationFailureReason;
use PDS\WP2FA\Method\VerificationResult;
use PDS\WP2FA\Method\MethodLifecycleService;

final class LifecycleServiceTest extends TestCase
{
    private UserId $user;
    private InstallationBinding $installation;
    private SessionDigest $session;
    private FakeMethodStore $methods;
    private FakeInteractionStore $interactions;
    private FakeSessionStore $sessions;
    private FakeTransactionManager $transactions;
    private FakeLifecycleProvider $provider;
    private MethodLifecycleService $service;

    protected function setUp(): void
    {
        $this->user = UserId::fromInt(7);
        $this->installation = new InstallationBinding(str_repeat('a', 64), 1);
        $this->session = new SessionDigest(str_repeat('b', 64));
        $this->methods = new FakeMethodStore();
        $this->interactions = new FakeInteractionStore();
        $this->sessions = new FakeSessionStore();
        $this->transactions = new FakeTransactionManager();
        $this->provider = new FakeLifecycleProvider('test');
        $this->service = new MethodLifecycleService(
            new ProviderRegistry([$this->provider]),
            $this->methods,
            $this->interactions,
            $this->sessions,
            $this->transactions,
            new SystemClock(),
        );
    }

    public function testEnrollmentCreatesAnActiveMethodButDoesNotSatisfyTheSession(): void
    {
        $start = $this->service->startEnrollment(
            $this->user,
            $this->installation,
            $this->session,
            ProviderKey::fromString('test'),
            PolicySnapshot::fromArray([]),
        );

        $method = $this->service->completeEnrollment(
            $start->reference(),
            $this->user,
            $this->installation,
            $this->session,
            ProviderKey::fromString('test'),
            new UntrustedInput(['code' => 'valid']),
        );

        self::assertSame(MethodStatus::ACTIVE, $method->status());
        self::assertSame(SessionState::PENDING, $this->sessions->state($this->user, $this->session));
        self::assertFalse($this->sessions->satisfied);
        self::assertSame(0, $this->provider->commitCalls);
        self::assertTrue($this->interactions->consumed);
    }

    public function testAuthenticationCommitsThroughTheTransactionAndSatisfiesOnlyTheBoundSession(): void
    {
        $existing = $this->methods->seedActive($this->user, $this->installation, ProviderKey::fromString('test'));
        $start = $this->service->startAuthentication(
            $this->user,
            $this->installation,
            $this->session,
            ProviderKey::fromString('test'),
            PolicySnapshot::fromArray([]),
            $existing->methodId(),
        );

        $outcome = $this->service->verifyAuthentication(
            $start->reference(),
            $this->user,
            $this->installation,
            $this->session,
            ProviderKey::fromString('test'),
            new UntrustedInput(['proof' => 'valid']),
        );

        self::assertTrue($outcome->succeeded());
        self::assertSame($existing->methodId(), $outcome->methodId());
        self::assertTrue($this->sessions->satisfied);
        self::assertSame(1, $this->provider->commitCalls);
        self::assertSame(1, $this->methods->authenticatedCalls);
        self::assertSame(1, $this->transactions->calls);
    }

    public function testBindingMismatchIsRejectedBeforeProviderVerification(): void
    {
        $existing = $this->methods->seedActive($this->user, $this->installation, ProviderKey::fromString('test'));
        $start = $this->service->startAuthentication(
            $this->user,
            $this->installation,
            $this->session,
            ProviderKey::fromString('test'),
            PolicySnapshot::fromArray([]),
            $existing->methodId(),
        );

        $this->expectException(\PDS\WP2FA\Method\InteractionRejected::class);
        $this->service->verifyAuthentication(
            $start->reference(),
            $this->user,
            $this->installation,
            new SessionDigest(str_repeat('c', 64)),
            ProviderKey::fromString('test'),
            new UntrustedInput(['proof' => 'valid']),
        );

        self::assertSame(0, $this->provider->verifyCalls);
        self::assertFalse($this->sessions->satisfied);
    }

    public function testFailedVerificationLeavesInteractionAndSessionPending(): void
    {
        $existing = $this->methods->seedActive($this->user, $this->installation, ProviderKey::fromString('test'));
        $start = $this->service->startAuthentication(
            $this->user,
            $this->installation,
            $this->session,
            ProviderKey::fromString('test'),
            PolicySnapshot::fromArray([]),
            $existing->methodId(),
        );
        $this->provider->shouldVerify = false;

        $outcome = $this->service->verifyAuthentication(
            $start->reference(),
            $this->user,
            $this->installation,
            $this->session,
            ProviderKey::fromString('test'),
            new UntrustedInput(['proof' => 'invalid']),
        );

        self::assertFalse($outcome->succeeded());
        self::assertSame(VerificationFailureReason::INVALID_PROOF, $outcome->failureReason());
        self::assertFalse($this->sessions->satisfied);
        self::assertFalse($this->interactions->consumed);
        self::assertSame(0, $this->provider->commitCalls);
        self::assertSame(0, $this->transactions->calls);
    }
}

final class FakeLifecycleProvider implements AuthenticationMethodProvider
{
    private ProviderKey $providerKey;
    public bool $shouldVerify = true;
    public int $verifyCalls = 0;
    public int $commitCalls = 0;

    public function __construct(string $key)
    {
        $this->providerKey = ProviderKey::fromString($key);
    }

    public function key(): ProviderKey { return $this->providerKey; }

    public function capabilities(): ProviderCapabilities
    {
        return new ProviderCapabilities(true, true, true, false, true, false);
    }

    public function startEnrollment(ProviderContext $context): ProviderStart
    {
        return ProviderStart::withoutReference(new ProviderPublicPayload([]), new ProviderServerState([]));
    }

    public function completeEnrollment(ProviderContext $context, ProviderStart $start, UntrustedInput $input): EnrollmentResult
    {
        return new EnrollmentResult(
            new MethodDraft(
                $context->userId(),
                $context->installation(),
                $context->providerKey(),
                1,
                FriendlyLabel::fromString('Test method'),
                new ProviderData(1, ['opaque' => 'state']),
            ),
            SafeMetadata::fromArray(['source' => 'test']),
        );
    }

    public function startVerification(ProviderContext $context): ProviderStart
    {
        return ProviderStart::withoutReference(new ProviderPublicPayload([]), new ProviderServerState([]));
    }

    public function verify(ProviderContext $context, ProviderStart $start, UntrustedInput $input): VerificationResult
    {
        ++$this->verifyCalls;
        if (!$this->shouldVerify) {
            return VerificationResult::failure(VerificationFailureReason::INVALID_PROOF);
        }

        $method = $context->methodSnapshot()->first()->methodId();

        return VerificationResult::success(
            $method,
            new TestVerificationCommit($this->providerKey),
            SafeMetadata::fromArray(['proof' => 'accepted']),
        );
    }

    public function commitVerification(ProviderContext $context, VerificationResult $result): VerificationCommit
    {
        ++$this->commitCalls;
        return $result->commit();
    }

    public function revoke(ProviderContext $context, MethodRecord $method, \PDS\WP2FA\Method\RevocationReason $reason): void
    {
    }
}

final class TestVerificationCommit implements VerificationCommit
{
    public function __construct(private ProviderKey $providerKey) {}
    public function providerKey(): ProviderKey { return $this->providerKey; }
}

final class FakeTransactionManager implements TransactionManager
{
    public int $calls = 0;
    public function transaction(callable $operation): mixed { ++$this->calls; return $operation(); }
}

final class FakeSessionStore implements SessionStore
{
    public bool $satisfied = false;
    public function state(UserId $userId, SessionDigest $session): SessionState
    {
        return $this->satisfied ? SessionState::SATISFIED : SessionState::PENDING;
    }
    public function satisfy(UserId $userId, SessionDigest $session): void { $this->satisfied = true; }
    public function invalidate(UserId $userId, SessionDigest $session): void { $this->satisfied = false; }
}

final class FakeInteractionStore implements InteractionStore
{
    /** @var array<string, Interaction> */
    public array $items = [];
    public bool $consumed = false;
    public function create(Interaction $interaction): void { $this->items[$interaction->id()->value()] = $interaction; }
    public function find(InteractionId $id): ?Interaction { return $this->items[$id->value()] ?? null; }
    public function findForUpdate(InteractionId $id): ?Interaction { return $this->find($id); }
    public function consume(Interaction $interaction, DateTimeImmutable $at): void { $this->consumed = true; }
    public function revokePendingAuthentication(UserId $userId, InstallationBinding $installation, SessionDigest $session): void {}
}

final class FakeMethodStore implements MethodStore
{
    /** @var array<string, MethodRecord> */
    public array $items = [];
    public int $authenticatedCalls = 0;

    public function seedActive(UserId $user, InstallationBinding $installation, ProviderKey $provider): MethodRecord
    {
        $record = new MethodRecord(
            MethodId::fromString('method-' . (count($this->items) + 1) . '-123456'),
            $user,
            $installation,
            $provider,
            1,
            FriendlyLabel::fromString('Existing'),
            MethodStatus::ACTIVE,
            new DateTimeImmutable('2026-08-24T00:00:00+00:00'),
            new DateTimeImmutable('2026-08-24T00:00:00+00:00'),
            null,
            null,
            1,
        );
        $this->items[$record->methodId()->value()] = $record;
        return $record;
    }

    public function create(MethodDraft $draft, DateTimeImmutable $at): MethodRecord
    {
        $record = new MethodRecord(
            MethodId::fromString('method-new-' . (count($this->items) + 1)),
            $draft->userId(),
            $draft->installation(),
            $draft->providerKey(),
            $draft->schemaVersion(),
            $draft->label(),
            MethodStatus::ACTIVE,
            $at,
            $at,
            null,
            null,
            1,
        );
        $this->items[$record->methodId()->value()] = $record;
        return $record;
    }

    public function find(UserId $userId, InstallationBinding $installation, MethodId $methodId): ?MethodRecord
    {
        $record = $this->items[$methodId->value()] ?? null;
        return $record !== null && $record->userId()->equals($userId) && $record->installation()->equals($installation) ? $record : null;
    }
    public function findForUpdate(UserId $userId, InstallationBinding $installation, MethodId $methodId): ?MethodRecord { return $this->find($userId, $installation, $methodId); }
    public function activeFor(UserId $userId, InstallationBinding $installation, ProviderKey $provider): array
    {
        return array_values(array_filter($this->items, static fn (MethodRecord $record): bool => $record->userId()->equals($userId) && $record->installation()->equals($installation) && $record->providerKey()->equals($provider) && $record->status() === MethodStatus::ACTIVE));
    }
    public function markAuthenticated(MethodRecord $method, VerificationCommit $commit, DateTimeImmutable $at): void { ++$this->authenticatedCalls; }
    public function retainedCount(UserId $userId, InstallationBinding $installation): int { return count($this->items); }
    public function revoke(MethodRecord $method, \PDS\WP2FA\Method\Revocation $revocation): void {}
    public function replace(MethodRecord $old, MethodDraft $replacement, \PDS\WP2FA\Method\Revocation $revocation, DateTimeImmutable $at): MethodRecord { return $this->create($replacement, $at); }
}
