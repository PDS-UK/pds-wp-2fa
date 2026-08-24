<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Integration;

use DateTimeImmutable;
use DateTimeZone;
use PDS\WP2FA\Crypto\RecoveryCodeRecord;
use PDS\WP2FA\Crypto\RecoveryCodeStore;
use PDS\WP2FA\Crypto\UnixClock;
use PDS\WP2FA\Http\AuthenticationSnapshot;
use PDS\WP2FA\Http\RateLimitDecision;
use PDS\WP2FA\Http\RateLimiter;
use PDS\WP2FA\Http\UrlGenerator;
use PDS\WP2FA\Identity\IdentityBindingReader;
use PDS\WP2FA\Identity\InstallationBinding as IdentityInstallationBinding;
use PDS\WP2FA\Method\AuthenticationMethodProvider;
use PDS\WP2FA\Method\Clock;
use PDS\WP2FA\Method\EnrollmentResult;
use PDS\WP2FA\Method\FriendlyLabel;
use PDS\WP2FA\Method\InstallationBinding;
use PDS\WP2FA\Method\Interaction;
use PDS\WP2FA\Method\InteractionId;
use PDS\WP2FA\Method\InteractionStore;
use PDS\WP2FA\Method\LastUsedAt;
use PDS\WP2FA\Method\MethodDraft;
use PDS\WP2FA\Method\MethodId;
use PDS\WP2FA\Method\MethodRecord;
use PDS\WP2FA\Method\MethodStore;
use PDS\WP2FA\Method\MethodStatus;
use PDS\WP2FA\Method\PolicySnapshot;
use PDS\WP2FA\Method\ProviderCapabilities;
use PDS\WP2FA\Method\ProviderCommit;
use PDS\WP2FA\Method\ProviderContext;
use PDS\WP2FA\Method\ProviderData;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\ProviderPublicPayload;
use PDS\WP2FA\Method\ProviderRegistry;
use PDS\WP2FA\Method\ProviderServerState;
use PDS\WP2FA\Method\ProviderStart;
use PDS\WP2FA\Method\RecoveryCodeResult;
use PDS\WP2FA\Method\Revocation;
use PDS\WP2FA\Method\SessionDigest;
use PDS\WP2FA\Method\SessionState;
use PDS\WP2FA\Method\TransactionManager;
use PDS\WP2FA\Method\UntrustedInput;
use PDS\WP2FA\Method\UserId;
use PDS\WP2FA\Method\VerificationCommit;
use PDS\WP2FA\Method\VerificationResult;
use PDS\WP2FA\Method\RevocationReason;
use PDS\WP2FA\Persistence\Wpdb;

final class FrozenUnixClock implements UnixClock
{
    public function __construct(public int $time)
    {
    }

    public function now(): int
    {
        return $this->time;
    }
}

final class FrozenMethodClock implements Clock
{
    public function __construct(public DateTimeImmutable $time)
    {
    }

    public function now(): DateTimeImmutable
    {
        return $this->time;
    }
}

final class IdentityReaderFixture implements IdentityBindingReader
{
    public function __construct(private ?IdentityInstallationBinding $binding)
    {
    }

    public function read(): ?IdentityInstallationBinding
    {
        return $this->binding;
    }
}

final class FixtureUrls implements UrlGenerator
{
    public function adminPage(string $route, ?string $returnTo = null): string
    {
        return '/wp-admin/admin.php?page=pds-2fa&route=' . $route
            . ($returnTo === null ? '' : '&pds_return_to=' . rawurlencode($returnTo));
    }

    public function adminPost(string $action): string
    {
        return '/wp-admin/admin-post.php?action=' . $action;
    }

    public function login(string $returnTo): string
    {
        return '/wp-login.php?redirect_to=' . rawurlencode($returnTo);
    }
}

final class InMemoryRecoveryStoreFixture implements RecoveryCodeStore
{
    /** @var list<RecoveryCodeRecord> */
    private array $records;

    /** @var array<string, bool> */
    private array $used = [];

    public function __construct(array $records, private bool $consumeSucceeds = true)
    {
        $this->records = $records;
    }

    public function unused(string $generationId): iterable
    {
        return array_values(array_filter(
            $this->records,
            fn (RecoveryCodeRecord $record): bool => !isset($this->used[$record->id()]),
        ));
    }

    public function consumeIfUnused(string $codeId): bool
    {
        if (!$this->consumeSucceeds || isset($this->used[$codeId])) {
            return false;
        }

        $this->used[$codeId] = true;

        return true;
    }
}

final class ThresholdRateLimiterFixture implements RateLimiter
{
    /** @var array<string, int> */
    private array $failures = [];

    public function check(string $operation, AuthenticationSnapshot $authentication): RateLimitDecision
    {
        $count = $this->failures[$this->key($operation, $authentication)] ?? 0;

        return match (true) {
            $count >= 20 => RateLimitDecision::limited(3600),
            $count >= 10 => RateLimitDecision::limited(300),
            $count >= 5 => RateLimitDecision::limited(30),
            default => RateLimitDecision::permit(),
        };
    }

    public function recordFailure(string $operation, AuthenticationSnapshot $authentication): void
    {
        $key = $this->key($operation, $authentication);
        $this->failures[$key] = ($this->failures[$key] ?? 0) + 1;
    }

    public function advanceWindow(): void
    {
        $this->failures = [];
    }

    private function key(string $operation, AuthenticationSnapshot $authentication): string
    {
        $installation = $authentication->installation();

        return $operation . ':' . $authentication->userId()?->value()
            . ':' . $installation?->hash() . ':' . $installation?->epoch();
    }
}

final class FixtureSessionStore implements \PDS\WP2FA\Method\SessionStore
{
    /** @var array<string, SessionState> */
    private array $states = [];

    public function state(UserId $user, SessionDigest $session): SessionState
    {
        return $this->states[$this->key($user, $session)] ?? SessionState::PENDING;
    }

    public function satisfy(UserId $user, SessionDigest $session): void
    {
        $this->states[$this->key($user, $session)] = SessionState::SATISFIED;
    }

    public function invalidate(UserId $user, SessionDigest $session): void
    {
        $this->states[$this->key($user, $session)] = SessionState::INVALIDATED;
    }

    private function key(UserId $user, SessionDigest $session): string
    {
        return $user->value() . ':' . $session->value();
    }
}

final class FixtureInteractionStore implements InteractionStore
{
    /** @var array<string, Interaction> */
    private array $interactions = [];

    /** @var array<string, bool> */
    private array $consumed = [];

    /** @var list<SessionDigest> */
    public array $revokedSessions = [];

    public function create(Interaction $interaction): void
    {
        $this->interactions[$interaction->id()->value()] = $interaction;
    }

    public function find(InteractionId $id): ?Interaction
    {
        return $this->interactions[$id->value()] ?? null;
    }

    public function findForUpdate(InteractionId $id): ?Interaction
    {
        if (isset($this->consumed[$id->value()])) {
            return null;
        }

        return $this->find($id);
    }

    public function consume(Interaction $interaction, DateTimeImmutable $at): void
    {
        $this->consumed[$interaction->id()->value()] = true;
    }

    public function revokePendingAuthentication(UserId $user, InstallationBinding $installation, SessionDigest $session): void
    {
        $this->revokedSessions[] = $session;
    }
}

final class FixtureMethodStore implements MethodStore
{
    /** @var array<string, MethodRecord> */
    public array $records = [];

    public int $authenticated = 0;

    public function create(MethodDraft $draft, DateTimeImmutable $at): MethodRecord
    {
        $method = new MethodRecord(
            MethodId::fromString('fixture-method-' . (count($this->records) + 1)),
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
            LastUsedAt::never(),
        );
        $this->records[$method->methodId()->value()] = $method;

        return $method;
    }

    public function find(UserId $user, InstallationBinding $installation, MethodId $methodId): ?MethodRecord
    {
        $method = $this->records[$methodId->value()] ?? null;

        return $method !== null && $method->userId()->equals($user)
            && $method->installation()->equals($installation) ? $method : null;
    }

    public function findForUpdate(UserId $user, InstallationBinding $installation, MethodId $methodId): ?MethodRecord
    {
        return $this->find($user, $installation, $methodId);
    }

    public function activeFor(UserId $user, InstallationBinding $installation, ProviderKey $provider): array
    {
        return array_values(array_filter($this->records, static fn (MethodRecord $method): bool =>
            $method->isActive() && $method->userId()->equals($user)
            && $method->installation()->equals($installation)
            && $method->providerKey()->equals($provider)
        ));
    }

    public function markAuthenticated(MethodRecord $method, VerificationCommit $commit, DateTimeImmutable $at): void
    {
        ++$this->authenticated;
    }

    public function retainedCount(UserId $user, InstallationBinding $installation): int
    {
        return count($this->activeFor($user, $installation, ProviderKey::fromString('totp')));
    }

    public function revoke(MethodRecord $method, Revocation $revocation): void
    {
    }

    public function replace(MethodRecord $old, MethodDraft $replacement, Revocation $revocation, DateTimeImmutable $at): MethodRecord
    {
        return $this->create($replacement, $at);
    }
}

final class FixtureTransactionManager implements TransactionManager
{
    public function transaction(callable $operation): mixed
    {
        return $operation();
    }
}

final class FixtureProvider implements AuthenticationMethodProvider
{
    private ProviderKey $key;

    public function __construct(string $key = 'totp')
    {
        $this->key = ProviderKey::fromString($key);
    }

    public function key(): ProviderKey
    {
        return $this->key;
    }

    public function capabilities(): ProviderCapabilities
    {
        return new ProviderCapabilities(true, true, true, false, true, false);
    }

    public function startEnrollment(ProviderContext $context): ProviderStart
    {
        return ProviderStart::withoutReference(
            new ProviderPublicPayload(['provider' => $this->key->value()]),
            new ProviderServerState(['operation' => 'enrollment']),
        );
    }

    public function completeEnrollment(ProviderContext $context, ProviderStart $start, UntrustedInput $input): EnrollmentResult
    {
        return new EnrollmentResult(
            new MethodDraft(
                $context->userId(),
                $context->installation(),
                $this->key,
                1,
                FriendlyLabel::fromString('Fixture authenticator'),
                new ProviderData(1, ['fixture' => true]),
            ),
            \PDS\WP2FA\Method\SafeMetadata::fromArray(['operation' => 'enrollment']),
        );
    }

    public function startVerification(ProviderContext $context): ProviderStart
    {
        return ProviderStart::withoutReference(
            new ProviderPublicPayload(['provider' => $this->key->value()]),
            new ProviderServerState(['challenge' => $context->challenge()->value()]),
        );
    }

    public function verify(ProviderContext $context, ProviderStart $start, UntrustedInput $input): VerificationResult
    {
        if (($input->asArray()['invalid'] ?? false) === true) {
            return VerificationResult::failure(\PDS\WP2FA\Method\VerificationFailureReason::INVALID_PROOF);
        }

        return VerificationResult::success(
            $context->methodSnapshot()->first()->methodId(),
            new ProviderCommit($this->key, \PDS\WP2FA\Method\SafeMetadata::fromArray(['proof' => 'accepted'])),
            \PDS\WP2FA\Method\SafeMetadata::fromArray(['proof' => 'accepted']),
        );
    }

    public function commitVerification(ProviderContext $context, VerificationResult $result): VerificationCommit
    {
        return new ProviderCommit($this->key, \PDS\WP2FA\Method\SafeMetadata::fromArray(['commit' => 'fixture']));
    }

    public function revoke(ProviderContext $context, MethodRecord $method, \PDS\WP2FA\Method\RevocationReason $reason): void
    {
    }
}

final class FixtureWpdb implements Wpdb
{
    /** @var list<string> */
    public array $queries = [];

    /** @var list<string> */
    public array $prepared = [];

    /** @var array<string, mixed>|null */
    public ?array $row = ['schema_version' => 1, 'state' => 'ready'];

    public function prefix(): string
    {
        return 'wp_';
    }

    public function prepare(string $query, mixed ...$args): string
    {
        $this->prepared[] = $query;

        return $query;
    }

    public function query(string $query): int|false
    {
        $this->queries[] = $query;

        return 1;
    }

    public function get_var(string $query): mixed
    {
        return null;
    }

    public function get_row(string $query): mixed
    {
        return $this->row;
    }

    public function get_results(string $query): array
    {
        return [];
    }

    public function get_charset_collate(): string
    {
        return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
    }

    public function get_error(): string
    {
        return '';
    }
}
