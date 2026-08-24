<?php

declare(strict_types=1);

namespace PDS\WP2FA\Tests\Unit\Http;

use PDS\WP2FA\Http\AccessiblePageRenderer;
use PDS\WP2FA\Http\AllowAllRateLimiter;
use PDS\WP2FA\Http\AuthenticationContextProvider;
use PDS\WP2FA\Http\AuthenticationSnapshot;
use PDS\WP2FA\Http\CallableCapabilityChecker;
use PDS\WP2FA\Http\CallableNonceFieldProvider;
use PDS\WP2FA\Http\CallableNonceVerifier;
use PDS\WP2FA\Http\CallableReauthenticationVerifier;
use PDS\WP2FA\Http\CallableUrlGenerator;
use PDS\WP2FA\Http\FactorOperationResult;
use PDS\WP2FA\Http\FactorOperations;
use PDS\WP2FA\Http\HttpRequest;
use PDS\WP2FA\Http\LoginRedirector;
use PDS\WP2FA\Http\Route;
use PDS\WP2FA\Http\RouteController;
use PDS\WP2FA\Http\RouteGate;
use PDS\WP2FA\Http\RateLimitDecision;
use PDS\WP2FA\Http\RateLimiter;
use PDS\WP2FA\Method\InteractionReference;
use PDS\WP2FA\Method\ProviderKey;
use PDS\WP2FA\Method\SessionDigest;
use PDS\WP2FA\Method\UntrustedInput;
use PDS\WP2FA\Method\UserId;
use PDS\WP2FA\WordPress\GateDecision;
use PDS\WP2FA\WordPress\RequestContext;
use PDS\WP2FA\WordPress\RequestType;
use PDS\WP2FA\WordPress\SafeRedirectTarget;
use PHPUnit\Framework\TestCase;

final class RouteBoundaryTest extends TestCase
{
    public function testPendingAdminAndAjaxRequestsAreStoppedAtTheEarlyBoundary(): void
    {
        $snapshot = $this->pending(AuthenticationSnapshot::MODE_CHALLENGE);
        $gate = new RouteGate($this->provider($snapshot), $this->urls());

        $admin = $gate->decide(new RequestContext(RequestType::ORDINARY_ADMIN, '/wp-admin/', null, null));
        self::assertSame(GateDecision::REDIRECT, $admin->outcome());
        self::assertSame(302, $admin->status());
        self::assertStringContainsString('route=challenge', (string) $admin->target());

        $ajax = $gate->decide(new RequestContext(RequestType::AJAX, '/wp-admin/admin-ajax.php', 'other', null));
        self::assertSame(GateDecision::DENY, $ajax->outcome());
        self::assertSame(403, $ajax->status());
        self::assertSame('pds_wp_2fa_pending', $ajax->code());
    }

    public function testCookieRestIsDeniedButOtherAuthenticationChannelsAreBypassed(): void
    {
        $gate = new RouteGate($this->provider($this->pending(AuthenticationSnapshot::MODE_CHALLENGE)), $this->urls());

        $rest = $gate->decide(new RequestContext(RequestType::REST_COOKIE, '/wp-json/pds', null, null));
        self::assertSame(GateDecision::DENY, $rest->outcome());
        self::assertSame(403, $rest->status());
        self::assertSame('pds_wp_2fa_pending', $rest->code());

        $applicationPassword = $gate->decide(new RequestContext(RequestType::REST_APPLICATION_PASSWORD, '/wp-json/pds', null, null));
        self::assertSame(GateDecision::BYPASS, $applicationPassword->outcome());

        $nonCookie = $gate->decide(new RequestContext(RequestType::REST_NON_COOKIE, '/wp-json/pds', null, null));
        self::assertSame(GateDecision::BYPASS, $nonCookie->outcome());

        $xmlRpc = $gate->decide(new RequestContext(RequestType::XML_RPC, '/xmlrpc.php', null, null));
        self::assertSame(GateDecision::BYPASS, $xmlRpc->outcome());
    }

    public function testIdentityFailureReturns503InsteadOfTrustingUserMeta(): void
    {
        $gate = new RouteGate($this->provider(AuthenticationSnapshot::unavailable()), $this->urls());
        $decision = $gate->decide(new RequestContext(RequestType::REST_COOKIE, '/wp-json/pds', null, null));

        self::assertSame(GateDecision::DENY, $decision->outcome());
        self::assertSame(503, $decision->status());
        self::assertSame('pds_wp_2fa_unavailable', $decision->code());
    }

    public function testChallengeRequiresItsOwnNonceAndDoesNotForwardPasswordFallback(): void
    {
        $operations = new FakeOperations(FactorOperationResult::success());
        $controller = $this->controller(
            $this->pending(AuthenticationSnapshot::MODE_CHALLENGE),
            $operations,
            nonceValid: true,
        );
        $request = $this->request(
            Route::CHALLENGE_ACTION,
            [
                'interaction_reference' => 'challenge-ref',
                'proof' => '123456',
                'password' => 'primary-password-must-not-cross-factor-seam',
                'pds_return_to' => 'https://example.test/wp-admin/reports',
            ],
        );

        $response = $controller->handle($request);

        self::assertSame(303, $response->status());
        self::assertSame('https://example.test/wp-admin/reports', $response->headers()['Location']);
        self::assertSame('authenticate', $operations->lastOperation);
        self::assertArrayNotHasKey('password', $operations->lastInput);
        self::assertSame(['proof' => '123456'], $operations->lastInput);
    }

    public function testInvalidNonceStopsBeforeProviderAndClearsSubmittedProofFromHtml(): void
    {
        $operations = new FakeOperations(FactorOperationResult::success());
        $controller = $this->controller(
            $this->pending(AuthenticationSnapshot::MODE_CHALLENGE),
            $operations,
            nonceValid: false,
        );
        $response = $controller->handle($this->request(Route::CHALLENGE_ACTION, [
            'interaction_reference' => 'challenge-ref',
            'proof' => 'secret-proof-value',
        ]));

        self::assertSame(403, $response->status());
        self::assertStringContainsString('form has expired', $response->body());
        self::assertStringNotContainsString('secret-proof-value', $response->body());
        self::assertNull($operations->lastOperation);
    }

    public function testRateLimiterReturns429AndDoesNotInvokeProvider(): void
    {
        $operations = new FakeOperations(FactorOperationResult::success());
        $controller = $this->controller(
            $this->pending(AuthenticationSnapshot::MODE_CHALLENGE),
            $operations,
            rateLimiter: new FakeRateLimiter(RateLimitDecision::limited(45)),
        );
        $response = $controller->handle($this->request(Route::CHALLENGE_ACTION, [
            'interaction_reference' => 'challenge-ref',
            'proof' => '123456',
        ]));

        self::assertSame(429, $response->status());
        self::assertSame('45', $response->headers()['Retry-After']);
        self::assertStringContainsString('Too many verification attempts', $response->body());
        self::assertNull($operations->lastOperation);
    }

    public function testEnrollmentCompletionShowsRecoveryBundleOnceAndLeavesSessionPending(): void
    {
        $operations = new FakeOperations(FactorOperationResult::success([
            'recovery_codes' => ['ABCD-EFGH'],
        ]));
        $controller = $this->controller(
            $this->pending(AuthenticationSnapshot::MODE_ENROLLMENT_REQUIRED, activeMethod: false),
            $operations,
        );
        $response = $controller->handle($this->request(Route::ENROLLMENT_COMPLETE_ACTION, [
            'interaction_reference' => 'enrollment-ref',
            'proof' => '654321',
        ]));

        self::assertSame(200, $response->status());
        self::assertSame('no-store, no-cache, must-revalidate, max-age=0', $response->headers()['Cache-Control']);
        self::assertStringContainsString('ABCD-EFGH', $response->body());
        self::assertStringContainsString('Continue to verification', $response->body());
        self::assertStringNotContainsString('654321', $response->body());
        self::assertSame('completeEnrollment', $operations->lastOperation);
    }

    public function testRecoveryRegenerationRequiresFreshPasswordReauthentication(): void
    {
        $operations = new FakeOperations(FactorOperationResult::success());
        $controller = $this->controller(
            $this->satisfied(),
            $operations,
            reauthenticationValid: false,
        );
        $response = $controller->handle($this->request(Route::RECOVERY_REGENERATE_ACTION, [
            'password' => 'wrong-password',
        ]));

        self::assertSame(403, $response->status());
        self::assertStringContainsString('current password', $response->body());
        self::assertNull($operations->lastOperation);
    }

    public function testSafeLoginRedirectNeverRoutesAStaleExternalTargetIntoThePlugin(): void
    {
        $redirector = new LoginRedirector($this->targets(), $this->urls());
        $target = $redirector->redirect('https://evil.test/wp-admin/', $this->pending(AuthenticationSnapshot::MODE_CHALLENGE));

        self::assertStringStartsWith('https://example.test/wp-admin/admin.php', $target);
        self::assertStringContainsString('route=challenge', $target);
        self::assertStringNotContainsString('evil.test', $target);
    }

    private function controller(
        AuthenticationSnapshot $snapshot,
        FakeOperations $operations,
        bool $nonceValid = true,
        ?RateLimiter $rateLimiter = null,
        bool $reauthenticationValid = true,
    ): RouteController {
        return new RouteController(
            $this->provider($snapshot),
            $operations,
            new CallableNonceVerifier(static fn (): bool => $nonceValid),
            new CallableCapabilityChecker(static fn (): bool => true),
            $rateLimiter ?? new AllowAllRateLimiter(),
            new CallableReauthenticationVerifier(static fn (): bool => $reauthenticationValid),
            $this->targets(),
            new AccessiblePageRenderer(
                $this->urls(),
                new CallableNonceFieldProvider(static fn (string $action): string => '<input type="hidden" name="_wpnonce" value="nonce-' . $action . '">'),
            ),
            $this->urls(),
        );
    }

    private function request(string $action, array $body): HttpRequest
    {
        return HttpRequest::fromContext(
            'POST',
            '/wp-admin/admin-post.php',
            [],
            array_merge(['action' => $action, '_wpnonce' => 'nonce'], $body),
            [],
            new RequestContext(RequestType::ADMIN_POST, '/wp-admin/admin-post.php', $action, null),
        );
    }

    private function pending(string $mode, bool $activeMethod = true): AuthenticationSnapshot
    {
        return new AuthenticationSnapshot(
            UserId::fromInt(7),
            new SessionDigest('session-digest'),
            null,
            \PDS\WP2FA\Method\SessionState::PENDING,
            $mode,
            true,
            true,
            true,
            $activeMethod,
            true,
        );
    }

    private function satisfied(): AuthenticationSnapshot
    {
        return new AuthenticationSnapshot(
            UserId::fromInt(7),
            new SessionDigest('session-digest'),
            null,
            \PDS\WP2FA\Method\SessionState::SATISFIED,
            AuthenticationSnapshot::MODE_NOT_REQUIRED,
        );
    }

    private function provider(AuthenticationSnapshot $snapshot): AuthenticationContextProvider
    {
        return new class ($snapshot) implements AuthenticationContextProvider {
            public function __construct(private AuthenticationSnapshot $snapshot) {}
            public function snapshot(): AuthenticationSnapshot { return $this->snapshot; }
        };
    }

    private function targets(): SafeRedirectTarget
    {
        return new SafeRedirectTarget(
            static fn (string $target, string $fallback): string => str_contains($target, 'example.test') ? $target : $fallback,
            static fn (): string => 'https://example.test/wp-admin/',
        );
    }

    private function urls(): CallableUrlGenerator
    {
        return new CallableUrlGenerator(
            static fn (string $route, ?string $returnTo = null): string => 'https://example.test/wp-admin/admin.php?page=pds-2fa&route=' . $route,
            static fn (string $action): string => 'https://example.test/wp-admin/admin-post.php?action=' . $action,
            static fn (string $returnTo): string => 'https://example.test/wp-login.php?redirect_to=' . rawurlencode($returnTo),
        );
    }
}

final class FakeOperations implements FactorOperations
{
    public ?string $lastOperation = null;
    /** @var array<string, mixed> */
    public array $lastInput = [];

    public function __construct(private FactorOperationResult $result) {}

    public function beginEnrollment(AuthenticationSnapshot $authentication, ProviderKey $provider): FactorOperationResult
    {
        $this->lastOperation = 'beginEnrollment';
        return $this->result;
    }

    public function completeEnrollment(AuthenticationSnapshot $authentication, InteractionReference $interaction, UntrustedInput $input): FactorOperationResult
    {
        $this->lastOperation = 'completeEnrollment';
        $this->lastInput = $input->asArray();
        return $this->result;
    }

    public function cancelEnrollment(AuthenticationSnapshot $authentication, InteractionReference $interaction): FactorOperationResult
    {
        $this->lastOperation = 'cancelEnrollment';
        return $this->result;
    }

    public function authenticate(AuthenticationSnapshot $authentication, InteractionReference $interaction, UntrustedInput $input): FactorOperationResult
    {
        $this->lastOperation = 'authenticate';
        $this->lastInput = $input->asArray();
        return $this->result;
    }

    public function recover(AuthenticationSnapshot $authentication, InteractionReference $interaction, UntrustedInput $input): FactorOperationResult
    {
        $this->lastOperation = 'recover';
        $this->lastInput = $input->asArray();
        return $this->result;
    }

    public function regenerateRecovery(AuthenticationSnapshot $authentication, UntrustedInput $input): FactorOperationResult
    {
        $this->lastOperation = 'regenerateRecovery';
        $this->lastInput = $input->asArray();
        return $this->result;
    }
}

final class FakeRateLimiter implements RateLimiter
{
    public function __construct(private RateLimitDecision $decision) {}
    public function check(string $operation, AuthenticationSnapshot $authentication): RateLimitDecision { return $this->decision; }
    public function recordFailure(string $operation, AuthenticationSnapshot $authentication): void {}
}
